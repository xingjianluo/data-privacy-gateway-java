package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
import com.github.xingjianluo.dataprivacygatewayjava.model.Policy;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.ResolvedGrant;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.RequestDedupStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 批量访问编排（脱敏批量 + 授权明文导出批量）。
 * <ul>
 *   <li>规模：单批条数可配，REJECT 模式超限整批拒绝（{@link ReasonCode#REJECT_BATCH_TOO_LARGE}），
 *       TRUNCATE 模式截断到约定条数并在结果中以 truncated + TRUNCATED_BY_LIMIT 标明；</li>
 *   <li>耗时：整批处理开始即固定起始时刻与批量时限，超时整批失败、不返回任何条目视图；</li>
 *   <li>版本：批量开始时固定一个 {@link Policy} 快照与一个当前密钥版本，
 *       整批所有条目都对应这一确定版本，策略发布/密钥轮换的并发更新不会造成半新半旧；
 *       历史密文按信封自身 v 解密，轮换后批量导出仍可读；</li>
 *   <li>隔离：单条失败只影响该条（其 view 为 null），其他条正常返回；</li>
 *   <li>幂等：caller+requestId 去重，处理失败回滚占位，重试不重复计数；</li>
 *   <li>授权：导出前与交付前两次校验/复核，期间被并发撤销或过期则整批拒绝，不留明文。</li>
 * </ul>
 */
@Service
public class BatchService {

    private static final Logger LOG = LoggerFactory.getLogger(BatchService.class);

    private final PrivacyGateway gateway;
    private final PolicyStore policyStore;
    private final KeyStore keyStore;
    private final GrantService grantService;
    private final LimitGuard limitGuard;
    private final GatewayProperties properties;
    private final AuditService auditService;
    private final RequestDedupStore dedupStore;

    /** 测试支持：每处理一条后的延迟（毫秒），默认 0；用于确定性触发整批超时。 */
    private volatile long perItemDelayMillis = 0L;
    /** 测试支持：处理完第一条后的一次性回调（如并发撤销授权），默认无操作。 */
    private volatile Runnable afterFirstItemHook = () -> { };

    /** 测试支持：设置逐条延迟。 */
    public void setPerItemDelayMillis(long millis) {
        this.perItemDelayMillis = millis;
    }

    /** 测试支持：设置首批条目处理后的钩子。 */
    public void setAfterFirstItemHook(Runnable hook) {
        this.afterFirstItemHook = hook == null ? () -> { } : hook;
    }

    public BatchService(PrivacyGateway gateway, PolicyStore policyStore, KeyStore keyStore,
                        GrantService grantService, LimitGuard limitGuard, GatewayProperties properties,
                        AuditService auditService, RequestDedupStore dedupStore) {
        this.gateway = gateway;
        this.policyStore = policyStore;
        this.keyStore = keyStore;
        this.grantService = grantService;
        this.limitGuard = limitGuard;
        this.properties = properties;
        this.auditService = auditService;
        this.dedupStore = dedupStore;
    }

    /** 批量脱敏访问（与单条入口同一判定口径）。 */
    public BatchAccessResponse accessBatch(AccessRequest request, List<BatchItemRequest> items,
                                           String requestId) {
        validateShape(request.caller(), items);
        return runBatch(request.caller(), request.clearance(), request.rawRequested(),
                null, items, requestId, "BATCH_ACCESS");
    }

    /** 批量明文导出（限时授权，逐条范围校验）。 */
    public BatchAccessResponse exportBatch(String caller, Level clearance, String grantId,
                                           List<BatchItemRequest> items, String requestId) {
        validateShape(caller, items);
        // 授权严格校验：缺失/跨调用方/过期/撤销在这里受控拒绝并留痕
        ResolvedGrant grant = grantService.validate(caller, grantId);
        // 记录范围预检：拿着授权访问范围外记录，整批拒绝（一条越界也不处理），并留痕
        List<String> outside = items.stream()
                .map(BatchItemRequest::recordId)
                .filter(id -> !grant.recordScope().contains(id))
                .distinct()
                .toList();
        if (!outside.isEmpty()) {
            auditService.record(caller, "BATCH_EXPORT", "*", ReasonCode.GRANT_SCOPE_VIOLATION,
                    null, keyStore.currentVersion(), null,
                    "导出拒绝：存在授权记录范围之外的记录：" + outside,
                    java.util.Map.of("grantId", grant.grantId(),
                            "outOfScopeRecords", outside.toString()));
            throw new GatewayException(ReasonCode.GRANT_SCOPE_VIOLATION,
                    "记录超出授权范围，整批拒绝：" + outside);
        }
        return runBatch(caller, clearance, true, grant, items, requestId, "BATCH_EXPORT");
    }

    private void validateShape(String caller, List<BatchItemRequest> items) {
        if (caller == null || caller.isBlank()) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "必须提供调用方身份");
        }
        if (items == null || items.isEmpty()) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "批量请求至少包含一条记录");
        }
        for (BatchItemRequest item : items) {
            if (item == null || item.recordId() == null || item.recordId().isBlank()) {
                throw new GatewayException(ReasonCode.BAD_REQUEST, "每条请求都必须包含 recordId");
            }
        }
    }

    private BatchAccessResponse runBatch(String caller, Level clearance, boolean rawRequested,
                                         ResolvedGrant grant, List<BatchItemRequest> items,
                                         String requestId, String operation) {
        long start = System.nanoTime();
        long startMillis = System.currentTimeMillis();
        String dedupEventId = requestId == null ? null
                : ("batch-pending-" + caller + "-" + requestId);

        if (requestId != null) {
            RequestDedupStore.DedupEntry dup = dedupStore.tryAcquire(
                    caller, requestId, "PENDING", dedupEventId, startMillis);
            if (dup != null) {
                boolean inFlight = "PENDING".equals(dup.outcome());
                ReasonCode code = inFlight ? ReasonCode.DUPLICATE_REQUEST
                        : ReasonCode.DUPLICATE_REQUEST;
                auditService.record(caller, operation, "*", code,
                        null, keyStore.currentVersion(), null,
                        (inFlight ? "并发重复的批量 requestId 被拒绝（首个请求仍在处理），首事件="
                                : "重复提交的批量 requestId 被拒绝（已完成），首事件=")
                                + dup.firstAuditEventId(),
                        java.util.Map.of("requestId", requestId,
                                "firstEventId", String.valueOf(dup.firstAuditEventId()),
                                "state", String.valueOf(dup.outcome())));
                throw new GatewayException(ReasonCode.DUPLICATE_REQUEST,
                        inFlight ? "相同 requestId 的批量请求正在处理中，请勿并发重复提交，首事件="
                                        + dup.firstAuditEventId()
                                : "requestId 已处理完成，请勿重复提交，首事件="
                                        + dup.firstAuditEventId());
            }
        }

        Policy policy;
        int pinnedKeyVersion;
        List<BatchItemRequest> accepted;
        boolean truncated = false;
        ReasonCode batchReason = ReasonCode.ALLOWED;
        try {
            policy = policyStore.current();
            pinnedKeyVersion = keyStore.currentVersion();
            if (policy == null) {
                throw new GatewayException(ReasonCode.POLICY_VERSION_NOT_FOUND, "当前无可用策略版本");
            }

            // --- 规模守卫：条数上限，按既定 mode 拒绝或截断 ---
            int maxSize = properties.getBatch().getMaxBatchSize();
            if (items.size() > maxSize) {
                if (limitGuard.mode() == LimitMode.REJECT) {
                    throw new GatewayException(ReasonCode.REJECT_BATCH_TOO_LARGE,
                            "批量条数 " + items.size() + " 超过上限 " + maxSize
                                    + "（REJECT 模式：整批拒绝，未处理任何条目）");
                }
                int keep = Math.min(properties.getBatch().getMaxBatchAccepted(), maxSize);
                accepted = new ArrayList<>(items.subList(0, keep));
                truncated = true;
                batchReason = ReasonCode.TRUNCATED_BY_LIMIT;
                LOG.info("[{}] 批量超限截断：提交 {} 条，实际处理 {} 条", operation, items.size(), keep);
            } else {
                accepted = new ArrayList<>(items);
            }

            // --- 逐条处理：单条失败不外抛，不影响其他条 ---
            List<BatchItemResult> results = new ArrayList<>(accepted.size());
            int index = 0;
            for (BatchItemRequest item : accepted) {
                checkBatchElapsed(start, operation);
                BatchItemResult result = gateway.processBatchItem(
                        caller, clearance, item.recordId(), rawRequested, item.fields(),
                        grant, policy, pinnedKeyVersion, start,
                        "BATCH_EXPORT".equals(operation) ? "EXPORT" : "ACCESS");
                results.add(result);
                if (index == 0) {
                    // 首批条目处理完的一刻回调：供测试在“处理期间”并发撤销/更新
                    afterFirstItemHook.run();
                }
                index++;
                // 逐条延迟置于条目之后：既保证首批已完成（钩子时机确定），又让整批可超时
                if (perItemDelayMillis > 0) {
                    try {
                        Thread.sleep(perItemDelayMillis);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            }

            // --- 交付前复核授权：处理期间被并发撤销/过期则整批拒绝，不返回已解开结果 ---
            if (grant != null && !grantService.stillValid(grant, System.currentTimeMillis())) {
                throw new GatewayException(ReasonCode.GRANT_REVOKED,
                        "授权在批量处理期间被撤销或过期，整批拒绝交付（任何条目明文均不返回）");
            }
            checkBatchElapsed(start, operation);

            if (batchReason == ReasonCode.ALLOWED
                    && results.stream().anyMatch(r -> r.ok()
                    && (r.reason() == ReasonCode.MASKED_INSUFFICIENT_CLEARANCE
                        || r.reason() == ReasonCode.GRANT_SCOPE_VIOLATION
                        || r.reason() == ReasonCode.DENIED_UNAUTHORIZED_RAW_READ))) {
                // 整批结论取条目中“最严格”的一个（越范围/越权优先于脱敏）
                batchReason = results.stream()
                        .filter(BatchItemResult::ok)
                        .map(BatchItemResult::reason)
                        .filter(r -> r != ReasonCode.ALLOWED)
                        .max(java.util.Comparator.comparingInt(BatchService::severity))
                        .orElse(ReasonCode.ALLOWED);
            }

            String summaryEventId = auditService.record(caller, operation + "_SUMMARY", "*",
                    batchReason, policy.version(), pinnedKeyVersion, null,
                    "批量完成：提交=" + items.size() + " 处理=" + results.size()
                            + " 截断=" + truncated,
                    java.util.Map.of("submitted", String.valueOf(items.size()),
                            "processed", String.valueOf(results.size()),
                            "truncated", String.valueOf(truncated),
                            "requestId", String.valueOf(requestId),
                            "grantId", grant == null ? "" : grant.grantId()));

            if (requestId != null) {
                // 成功：用最终结论覆盖 PENDING 占位（同 eventId 键，记录最终结果）
                dedupStore.release(caller, requestId, dedupEventId);
                dedupStore.tryAcquire(caller, requestId, batchReason.name(), summaryEventId,
                        startMillis);
            }
            return new BatchAccessResponse(List.copyOf(results), policy.version(),
                    pinnedKeyVersion, truncated, batchReason, requestId, results.size());
        } catch (GatewayException e) {
            // 整批级失败：回滚幂等占位，使调用方可安全重试；不返回任何已处理视图
            if (requestId != null) {
                dedupStore.release(caller, requestId, dedupEventId);
            }
            auditService.record(caller, operation + "_FAIL", "*", e.code(),
                    policyStore.current() == null ? null : policyStore.current().version(),
                    keyStore.currentVersion(), null,
                    "批量整批失败：" + e.getMessage(),
                    java.util.Map.of("requestId", String.valueOf(requestId)));
            throw e;
        }
    }

    private void checkBatchElapsed(long startNanos, String operation) {
        long elapsedMillis = (System.nanoTime() - startNanos) / 1_000_000L;
        long limit = properties.getBatch().getMaxBatchElapsedMillis();
        if (elapsedMillis > limit) {
            throw new GatewayException(ReasonCode.REQUEST_TIMEOUT,
                    "批量处理耗时 " + elapsedMillis + "ms 超过上限 " + limit
                            + "ms（场景：" + operation + "，整批失败，不返回中间结果）");
        }
    }

    /** 定时清理过期的幂等记忆条目，默认每分钟一次。 */
    @Scheduled(fixedDelayString =
            "${privacy-gateway.retention.purge-interval-millis:60000}")
    public void scheduledDedupPurge() {
        int removed = dedupStore.purgeExpired(
                properties.getBatch().getIdempotencyTtlMillis(), System.currentTimeMillis());
        if (removed > 0) {
            LOG.info("批量幂等记忆清理：移除过期条目 {} 条", removed);
        }
    }

    /** 条目原因码严重度排序：越范围/越权 &gt; 脱敏 &gt; 允许。 */
    private static int severity(ReasonCode reason) {
        return switch (reason) {
            case GRANT_SCOPE_VIOLATION, DENIED_UNAUTHORIZED_RAW_READ -> 3;
            case MASKED_INSUFFICIENT_CLEARANCE -> 2;
            default -> 1;
        };
    }
}
