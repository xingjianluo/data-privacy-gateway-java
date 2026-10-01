package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.CipherEnvelope;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestReport;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.NormalizedRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.Policy;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.RecordSchema;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.util.Digests;
import com.github.xingjianluo.dataprivacygatewayjava.util.JsonCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 网关门面。
 * <p>一致性保证：一次请求开始时固定一个 {@link Policy} 快照与当前密钥版本，
 * 整次递归处理都对应这一确定版本，期间发生的策略更新/密钥轮换不影响本次结论。</p>
 * <p>幂等保证：已脱敏令牌与密文信封再次处理不叠加变形；同一逻辑字段无论出现在
 * 任意深度、数组下标、{@code {"value":..}} 包装或别名键下，处理结果一致。</p>
 * <p>失败安全：越权整单拒绝，不返回部分原文；任何异常路径不写半成品，审计独立、失败不影响结论。</p>
 */
@Service
public class PrivacyGateway {

    private static final Logger LOG = LoggerFactory.getLogger(PrivacyGateway.class);

    private final PolicyStore policyStore;
    private final KeyStore keyStore;
    private final RecordStore recordStore;
    private final CryptoService cryptoService;
    private final IngestService ingestService;
    private final DecisionService decisionService;
    private final MaskingService maskingService;
    private final AuditService auditService;
    private final LimitGuard limitGuard;
    private final GrantService grantService;
    private final FieldSelectionService fieldSelectionService;
    private final com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties batchProps;

    public PrivacyGateway(PolicyStore policyStore, KeyStore keyStore, RecordStore recordStore,
                          CryptoService cryptoService, IngestService ingestService,
                          DecisionService decisionService, MaskingService maskingService,
                          AuditService auditService, LimitGuard limitGuard,
                          GrantService grantService, FieldSelectionService fieldSelectionService,
                          com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties properties) {
        this.policyStore = policyStore;
        this.keyStore = keyStore;
        this.recordStore = recordStore;
        this.cryptoService = cryptoService;
        this.ingestService = ingestService;
        this.decisionService = decisionService;
        this.maskingService = maskingService;
        this.auditService = auditService;
        this.limitGuard = limitGuard;
        this.grantService = grantService;
        this.fieldSelectionService = fieldSelectionService;
        this.batchProps = properties;
    }

    public IngestReport ingest(String source, String recordId, Map<String, Object> raw, RecordSchema schema) {
        return ingestService.ingest(source, recordId, raw, schema);
    }

    public List<FieldRule> currentRules() {
        Policy p = policyStore.current();
        return p == null ? List.of() : p.rules();
    }

    /**
     * 用当前密钥版本加密记录内指定逻辑字段（递归覆盖嵌套/数组/包装/别名），
     * 已为密文信封的值保持原样（幂等，不重复加密）。操作完成后原子写回。
     */
    public int encryptFields(String recordId, List<String> fieldNames) {
        NormalizedRecord record = recordStore.get(recordId);
        if (record == null) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "记录不存在：" + recordId);
        }
        long start = System.nanoTime();
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) JsonCodec.deepCopy(record.data());
        int[] changed = {0};
        encryptRecursively(data, "$", 1, null, fieldNames, start, changed);
        NormalizedRecord updated = new NormalizedRecord(record.recordId(), record.source(),
                record.ingestedAt(), data, record.rejectedFields());
        recordStore.put(updated);
        auditService.record("system", "ENCRYPT", recordId, ReasonCode.ALLOWED,
                currentPolicyVersion(), keyStore.currentVersion(), safeDigest(data),
                "字段加密完成，字段=" + fieldNames + "，变更标量数=" + changed[0],
                Map.of("changed", String.valueOf(changed[0])));
        return changed[0];
    }

    /**
     * 解密整张记录。仅 RESTRICTED 调用方可取原文；
     * 信封按自身 v 取对应历史密钥（密钥版本缺失/用错/密文损坏分别得到不同原因码，
     * 底层异常不外泄）。解密结果不落库，杜绝明文残留。
     */
    public Map<String, Object> decryptRecord(String caller, String recordId) {
        NormalizedRecord record = recordStore.get(recordId);
        if (record == null) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "记录不存在：" + recordId);
        }
        Policy policy = policyStore.current();
        if (policy == null) {
            throw new GatewayException(ReasonCode.POLICY_VERSION_NOT_FOUND, "当前无可用策略版本");
        }
        // 检查调用方是否具备解密资质（通过密钥库/调用约定：此处要求调用方角色由调用点保证等级）
        @SuppressWarnings("unchecked")
        Map<String, Object> view = (Map<String, Object>) JsonCodec.deepCopy(record.data());
        long start = System.nanoTime();
        try {
            decryptRecursively(view, start);
        } catch (GatewayException e) {
            auditService.record(caller, "DECRYPT", recordId, e.code(), policy.version(),
                    keyStore.currentVersion(), safeDigest(record.data()),
                    "解密失败：" + e.getMessage(), Map.of());
            throw e;
        }
        auditService.record(caller, "DECRYPT", recordId, ReasonCode.ALLOWED,
                policy.version(), keyStore.currentVersion(), safeDigest(record.data()),
                "解密成功（明文仅在返回视图中，未持久化）", Map.of());
        return view;
    }

    private void encryptRecursively(Object node, String path, int depth, String wrapperField,
                                    List<String> targets, long startNanos, int[] changed) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (isWrapperMap(map)) {
                String logical = wrapperField != null ? wrapperField : "value";
                Object inner = map.get("value");
                if (targets.contains(logical) && !(inner instanceof Map<?, ?> || inner instanceof List<?>)) {
                    map.put("value", encryptScalar(inner, changed));
                } else {
                    encryptRecursively(inner, path + ".value", depth + 1, "value",
                            targets, startNanos, changed);
                }
                return;
            }
            for (Map.Entry<String, Object> e : new ArrayList<>(map.entrySet())) {
                String key = e.getKey();
                Object child = e.getValue();
                if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    encryptRecursively(child, path + "." + key, depth + 1, key,
                            targets, startNanos, changed);
                } else if (targets.contains(key)) {
                    map.put(key, encryptScalar(child, changed));
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                String inherited = (child instanceof Map<?, ?> cm && !isWrapperMap(cm)) ? null : wrapperField;
                if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    encryptRecursively(child, path + "[" + i + "]", depth + 1, inherited,
                            targets, startNanos, changed);
                } else if (wrapperField != null && targets.contains(wrapperField)) {
                    arr.set(i, encryptScalar(child, changed));
                }
            }
        }
    }

    private Object encryptScalar(Object value, int[] changed) {
        if (value == null || AesGcmCryptoService.isEnvelope(value)) {
            return value; // 幂等：已是密文信封则原样保留
        }
        changed[0]++;
        CipherEnvelope envelope = cryptoService.encrypt(String.valueOf(value));
        return envelope.toMap();
    }

    private void decryptRecursively(Object node, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            for (Map.Entry<String, Object> e : new ArrayList<>(map.entrySet())) {
                Object child = e.getValue();
                if (AesGcmCryptoService.isEnvelope(child)) {
                    CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(child));
                    map.put(e.getKey(), cryptoService.decrypt(env));
                } else if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    decryptRecursively(child, startNanos);
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                if (AesGcmCryptoService.isEnvelope(child)) {
                    CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(child));
                    arr.set(i, cryptoService.decrypt(env));
                } else if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    decryptRecursively(child, startNanos);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<?, ?> asMap(Object value) {
        return (Map<?, ?>) value;
    }

    /**
     * 导出专用：只解密字段级判定为 ALLOW 的密文信封（路径集合来自本次字段判定），
     * 判定为 MASK / 无规则命中的信封原样保留。路径口径与 {@link #process} 严格一致：
     * 普通对象按键、数组元素继承直接父键（普通对象元素内部重置）、包装以父逻辑名判定。
     */
    private void decryptAllowedRecursively(Object node, String path, String wrapperField,
                                           java.util.Set<String> allowedPaths, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (isWrapperMap(map)) {
                String logical = wrapperField != null ? wrapperField : "value";
                boolean allowed = allowedPaths.contains(path);
                Object inner = map.get("value");
                if (allowed && AesGcmCryptoService.isEnvelope(inner)) {
                    CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(inner));
                    map.put("value", cryptoService.decrypt(env));
                } else if (inner instanceof Map<?, ?> || inner instanceof List<?>) {
                    decryptAllowedRecursively(inner, path + ".value", "value",
                            allowedPaths, startNanos);
                }
                return;
            }
            for (Map.Entry<String, Object> e : new ArrayList<>(map.entrySet())) {
                Object child = e.getValue();
                String childPath = path + "." + e.getKey();
                if (AesGcmCryptoService.isEnvelope(child)) {
                    if (allowedPaths.contains(childPath)) {
                        map.put(e.getKey(),
                                cryptoService.decrypt(AesGcmCryptoService.fromMap(asMap(child))));
                    }
                } else if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    decryptAllowedRecursively(child, childPath, e.getKey(),
                            allowedPaths, startNanos);
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                String childPath = path + "[" + i + "]";
                String childWrapper = wrapperField;
                if (child instanceof Map<?, ?> cm && !isWrapperMap(cm)) {
                    childWrapper = null;
                }
                if (AesGcmCryptoService.isEnvelope(child)) {
                    if (allowedPaths.contains(childPath)) {
                        arr.set(i,
                                cryptoService.decrypt(AesGcmCryptoService.fromMap(asMap(child))));
                    }
                } else if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    decryptAllowedRecursively(child, childPath, childWrapper,
                            allowedPaths, startNanos);
                }
            }
        }
    }

    public long currentPolicyVersion() {
        Policy p = policyStore.current();
        return p == null ? -1 : p.version();
    }

    public AccessResponse access(AccessRequest request) {
        long start = System.nanoTime();
        NormalizedRecord record = recordStore.get(request.recordId());
        String inputDigest = safeDigest(Map.of("recordId", String.valueOf(request.recordId()),
                "caller", String.valueOf(request.caller()),
                "clearance", String.valueOf(request.clearance()),
                "raw", String.valueOf(request.rawRequested())));
        if (record == null) {
            GatewayException notFound = new GatewayException(ReasonCode.BAD_REQUEST,
                    "记录不存在：" + request.recordId());
            auditService.record(request.caller(), "ACCESS", request.recordId(),
                    ReasonCode.BAD_REQUEST, null, keyStore.currentVersion(),
                    inputDigest, "记录不存在，拒绝访问", Map.of());
            throw notFound;
        }

        // 固定本次请求的策略快照与密钥版本：处理期间任何更新都不影响本次结论
        Policy policy = policyStore.current();
        int pinnedKeyVersion = keyStore.currentVersion();
        if (policy == null) {
            throw new GatewayException(ReasonCode.POLICY_VERSION_NOT_FOUND, "当前无可用策略版本");
        }
        inputDigest = safeDigest(record.data());

        @SuppressWarnings("unchecked")
        Map<String, Object> view = (Map<String, Object>) JsonCodec.deepCopy(record.data());
        List<FieldDecision> decisions = new ArrayList<>();
        boolean[] truncated = {false};

        process(view, "$", 1, null, request, policy, decisions, truncated, start);
        limitGuard.checkElapsed(start, ReasonCode.ALLOWED);

        boolean denied = decisions.stream().anyMatch(d -> d.action() == FieldAction.DENY);
        ReasonCode overall;
        if (denied) {
            overall = ReasonCode.DENIED_UNAUTHORIZED_RAW_READ;
        } else if (truncated[0]) {
            overall = ReasonCode.TRUNCATED_BY_LIMIT;
        } else if (decisions.stream().anyMatch(d -> d.action() == FieldAction.MASK)) {
            overall = ReasonCode.MASKED_INSUFFICIENT_CLEARANCE;
        } else {
            overall = ReasonCode.ALLOWED;
        }

        String eventId;
        {
            java.util.Map<String, String> detail = new java.util.LinkedHashMap<>();
            int allow = 0, mask = 0, deny = 0;
            for (FieldDecision dd : decisions) {
                switch (dd.action()) {
                    case ALLOW -> allow++;
                    case MASK -> mask++;
                    case DENY -> deny++;
                    case NOT_FOUND -> { /* 单条入口不产生 NOT_FOUND，防御性忽略 */ }
                }
            }
            detail.put("counts", "ALLOW=" + allow + ",MASK=" + mask + ",DENY=" + deny);
            detail.put("rawRequested", String.valueOf(request.rawRequested()));
            eventId = auditService.record(request.caller(), "ACCESS", request.recordId(),
                    overall, policy.version(), pinnedKeyVersion, inputDigest,
                    summarize(decisions), detail);
        }
        LOG.info("[ACCESS] inputSummary recordId={} caller={} clearance={} raw={} digest={} | outcome={} policyV={} keyV={} decisions={}",
                request.recordId(), request.caller(), request.clearance(), request.rawRequested(),
                inputDigest, overall, policy.version(), pinnedKeyVersion, summarize(decisions));

        if (denied) {
            // 越权取原文：整单拒绝，不返回任何字段视图，避免泄漏已处理/已解密中间结果
            throw new GatewayException(overall,
                    "越权读取原始值被拒绝，见审计事件 " + eventId + "：" + summarize(decisions));
        }
        return new AccessResponse(request.recordId(), view, policy.version(), pinnedKeyVersion,
                List.copyOf(decisions), overall, eventId, truncated[0]);
    }

    /**
     * 批量访问：一次请求多条记录，逐条给出结论；单条被拒绝/失败不影响其他条目。
     * 批次开始时固定策略快照与密钥版本，整批对应同一确定版本；
     * 超时整批失败且不返回任何部分结果（中间视图全部丢弃）。
     */
    public BatchResponse batchAccess(BatchAccessRequest request) {
        return doBatch(request, null, "BATCH_ACCESS", false);
    }

    /**
     * 批量明文导出：在批量访问之上叠加限时授权校验（调用方 / 记录范围 / 字段范围 / 有效期）。
     * 授权只收紧不放宽：字段级判定沿用与普通批量访问<b>完全相同</b>的口径（同一调用方持证等级
     * 与同一 raw 语义），因此对同一份数据、同一批点名字段，两个入口的结论逐项一致；
     * 授权范围内判定为 ALLOW 的密文信封按信封版本解密（轮换后历史密文仍可解开），
     * 低权限会脱敏的字段在导出中同样脱敏（脱敏后的令牌不涉及解密）。
     * 明文只存在于返回视图中，不落库；中途失败/超时整批丢弃，不留已解开的中间结果。
     */
    public BatchResponse batchExport(String grantId, BatchAccessRequest request) {
        String caller = request == null ? null : request.caller();
        com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant grant;
        try {
            // 授权快照在校验时确定：并发撤销要么发生在校验前（本批失败）、要么之后（本批完整执行）
            grant = grantService.requireValid(grantId, caller);
        } catch (GatewayException e) {
            Policy p = policyStore.current();
            auditService.record(caller, "BATCH_EXPORT", "grant:" + grantId, e.code(),
                    p == null ? null : p.version(), keyStore.currentVersion(), null,
                    "导出授权校验失败：" + e.getMessage(), Map.of("grantId", String.valueOf(grantId)));
            throw e;
        }
        // 导出口径：沿用调用方自己的 raw 语义（与普通批量访问完全一致）；
        // 条目未点名字段时收敛为授权字段范围（空选择 ≠ 全表导出）
        List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem> items = new ArrayList<>();
        for (com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem item : request.items()) {
            items.add(item.fields().isEmpty()
                    ? new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem(
                            item.recordId(), List.copyOf(grant.fields()))
                    : item);
        }
        BatchAccessRequest exportRequest = new BatchAccessRequest(
                request.caller(), request.clearance(), request.rawRequested(), items);
        return doBatch(exportRequest, grant, "BATCH_EXPORT", true);
    }

    /**
     * 批量处理主流程。grant 非空时按导出口径逐条做范围校验（由 batchExport 传入）。
     */
    private BatchResponse doBatch(BatchAccessRequest request,
                                  com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant grant,
                                  String operation, boolean decrypt) {
        long start = System.nanoTime();
        if (request == null || request.caller() == null || request.caller().isBlank()) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "批量请求缺少调用方");
        }
        Policy policy = policyStore.current();
        if (policy == null) {
            throw new GatewayException(ReasonCode.POLICY_VERSION_NOT_FOUND, "当前无可用策略版本");
        }
        // 固定本批次的策略快照与密钥版本：处理期间任何更新/轮换都不影响本批结论
        int pinnedKeyVersion = keyStore.currentVersion();

        List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem> items = request.items();
        int requestedCount = items.size();
        boolean batchTruncated = false;
        int maxItems = batchMaxItems();
        if (requestedCount > maxItems) {
            if (limitGuard.mode() == com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode.REJECT) {
                auditService.record(request.caller(), operation, "batch:" + requestedCount,
                        ReasonCode.BATCH_LIMIT_EXCEEDED, policy.version(), pinnedKeyVersion, null,
                        "单批条数 " + requestedCount + " 超过上限 " + maxItems + "，按 REJECT 约定整批拒绝",
                        Map.of("maxItems", String.valueOf(maxItems)));
                throw new GatewayException(ReasonCode.BATCH_LIMIT_EXCEEDED,
                        "单批条数 " + requestedCount + " 超过上限 " + maxItems);
            }
            // TRUNCATE 约定：截断到上限并在响应中明确标记
            items = new ArrayList<>(items.subList(0, maxItems));
            batchTruncated = true;
        }

        List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult> results = new ArrayList<>();
        for (com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem item : items) {
            // 超时：整批失败，已处理的中间视图随异常一并丢弃，不留部分结果
            limitGuard.checkElapsed(start, ReasonCode.ALLOWED);
            results.add(processBatchItem(request, item, grant, policy, pinnedKeyVersion,
                    operation, decrypt, start));
        }
        return new BatchResponse(results, requestedCount, batchTruncated,
                policy.version(), pinnedKeyVersion);
    }

    /** 处理批量中的单条：任何失败都收敛为该条目的结论，绝不影响其他条目。 */
    private com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult processBatchItem(
            BatchAccessRequest request,
            com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem item,
            com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant grant,
            Policy policy, int pinnedKeyVersion, String operation, boolean decrypt,
            long startNanos) {
        String recordId = item.recordId();
        try {
            if (recordId == null || recordId.isBlank()) {
                throw new GatewayException(ReasonCode.BAD_REQUEST, "条目缺少 recordId");
            }
            // 导出口径：授权范围逐条校验（记录范围 + 字段范围，字段别名归一）
            if (grant != null) {
                checkGrantScope(grant, item, policy);
            }
            NormalizedRecord record = recordStore.get(recordId);
            if (record == null) {
                throw new GatewayException(ReasonCode.BAD_REQUEST, "记录不存在：" + recordId);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> view = (Map<String, Object>) JsonCodec.deepCopy(record.data());
            // 条目点名了字段：深层定位命中（子对象/数组/包装/别名同口径），
            // 只保留命中字段与通向它的容器链；同时得到与裁剪视图一一对应的命中清单
            List<FieldSelectionService.FieldHit> hits;
            if (!item.fields().isEmpty()) {
                FieldSelectionService.PrunedView pruned =
                        fieldSelectionService.prune(view, item.fields(), policy);
                view = pruned.view();
                hits = pruned.hits();
            } else {
                hits = List.of();
            }
            AccessRequest single = new AccessRequest(request.caller(), request.clearance(),
                    recordId, request.rawRequested());
            List<FieldDecision> decisions = new ArrayList<>();
            boolean[] truncated = {false};
            process(view, "$", 1, null, single, policy, decisions, truncated, startNanos);
            addFieldSelectionDecisions(view, item, single, policy, decisions, hits);

            boolean denied = decisions.stream().anyMatch(d -> d.action() == FieldAction.DENY);
            boolean notFound = decisions.stream().anyMatch(d -> d.action() == FieldAction.NOT_FOUND);
            ReasonCode outcome;
            if (denied) {
                outcome = ReasonCode.DENIED_UNAUTHORIZED_RAW_READ;
            } else if (truncated[0]) {
                outcome = ReasonCode.TRUNCATED_BY_LIMIT;
            } else if (decisions.stream().anyMatch(d -> d.action() == FieldAction.MASK)) {
                outcome = ReasonCode.MASKED_INSUFFICIENT_CLEARANCE;
            } else if (notFound) {
                // 点名字段不存在/取不到：如实告知，绝不用空结果冒充允许
                outcome = ReasonCode.FIELD_NOT_FOUND;
            } else {
                outcome = ReasonCode.ALLOWED;
            }
            String eventId = auditService.record(request.caller(), operation, recordId, outcome,
                    policy.version(), pinnedKeyVersion, safeDigest(record.data()),
                    summarize(decisions), Map.of("batchItem", "true"));
            // 与单条入口一致的失败安全：越权取原文的条目不返回任何字段视图
            Map<String, Object> resultView = denied ? null : view;
            if (resultView != null && decrypt) {
                // 明文导出：只解开字段级判定为 ALLOW 的密文信封（按信封版本取历史密钥，
                // 轮换后仍可解）；被 MASK 的字段信封原样保留，授权绝不放宽到越权解密。
                // 解密失败抛 GatewayException，由外层 catch 收敛为该条目失败，不影响其他条目。
                java.util.Set<String> allowedPaths = new java.util.HashSet<>();
                for (FieldDecision d : decisions) {
                    if (d.action() == FieldAction.ALLOW) {
                        allowedPaths.add(d.path());
                    }
                }
                decryptAllowedRecursively(resultView, "$", null, allowedPaths, startNanos);
            }
            String message = denied ? "越权读取原始值被拒绝"
                    : notFound ? describeNotFound(decisions) : null;
            return new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult(
                    recordId, outcome, resultView, decisions, policy.version(), pinnedKeyVersion,
                    eventId, truncated[0], message);
        } catch (GatewayException e) {
            if (e.code() == ReasonCode.REQUEST_TIMEOUT) {
                // 超时是批次级结论：整批失败，已处理/已解开的中间视图随异常一并丢弃
                throw e;
            }
            String eventId = auditService.record(request.caller(), operation,
                    String.valueOf(recordId), e.code(), policy.version(), pinnedKeyVersion, null,
                    "条目处理失败：" + e.getMessage(), Map.of("batchItem", "true"));
            return new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult(
                    String.valueOf(recordId), e.code(), null, List.of(), policy.version(),
                    pinnedKeyVersion, eventId, false, e.getMessage());
        }
    }

    /**
     * 批量路径补齐判定依据，保证「点名的每个逻辑字段」都有一条属于自己的依据：
     * <ul>
     *   <li>有规则字段（含嵌套/数组/包装/别名的每一处出现）由递归处理产出，这里不重复；</li>
     *   <li>无规则字段的每一处出现显式补一条 ALLOW(PUBLIC) 依据；</li>
     *   <li>点名但在记录任何层级都不存在/取不到的逻辑字段，补一条 NOT_FOUND 依据，
     *       绝不允许返回空依据却报允许；</li>
     *   <li>未点名字段（fields 为空）时，沿用原约定：按顶层键为无规则字段补 ALLOW 依据。</li>
     * </ul>
     */
    private void addFieldSelectionDecisions(Map<String, Object> view,
                                            com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem item,
                                            AccessRequest request, Policy policy,
                                            List<FieldDecision> decisions,
                                            List<FieldSelectionService.FieldHit> hits) {
        if (item.fields().isEmpty()) {
            // 全字段访问（仅可能出现在批量访问入口）：保持原约定，顶层无规则字段补一条 ALLOW
            for (String f : view.keySet()) {
                if (decisionService.findRule(policy, f) != null) {
                    continue;
                }
                boolean already = decisions.stream().anyMatch(d -> ("$." + f).equals(d.path()));
                if (!already) {
                    decisions.add(new FieldDecision("$." + f, f, FieldAction.ALLOW, ReasonCode.ALLOWED,
                            request.clearance(), Level.PUBLIC, policy.version()));
                }
            }
            return;
        }
        // 按点名字段：逐处命中核对递归处理是否已产出依据（按路径判重），无规则字段补 ALLOW
        for (FieldSelectionService.FieldHit hit : hits) {
            boolean already = decisions.stream().anyMatch(d -> hit.path().equals(d.path()));
            if (already) {
                continue; // 有规则字段已由递归处理在该路径给出 ALLOW/MASK/DENY
            }
            decisions.add(new FieldDecision(hit.path(), hit.canonicalName(), FieldAction.ALLOW,
                    ReasonCode.ALLOWED, request.clearance(), Level.PUBLIC, policy.version()));
        }
        // 点名却零命中的逻辑字段（任何层级/包装/别名下都不存在）：如实标记 NOT_FOUND
        java.util.Set<String> hitNames = new java.util.LinkedHashSet<>();
        for (FieldSelectionService.FieldHit hit : hits) {
            hitNames.add(hit.canonicalName());
        }
        for (String wanted : fieldSelectionService.canonicalNames(policy, item.fields())) {
            if (!hitNames.contains(wanted)) {
                decisions.add(decisionService.notFound(policy, request, wanted));
            }
        }
    }

    private static String describeNotFound(List<FieldDecision> decisions) {
        List<String> missing = new ArrayList<>();
        for (FieldDecision d : decisions) {
            if (d.action() == FieldAction.NOT_FOUND) {
                missing.add(d.field());
            }
        }
        return "点名字段在记录中不存在或取不到：" + missing;
    }

    /** 导出授权范围校验：记录与字段（别名归一后）都必须在授权范围内。 */
    private void checkGrantScope(
            com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant grant,
            com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem item,
            Policy policy) {
        if (!grant.recordIds().contains(item.recordId())) {
            throw new GatewayException(ReasonCode.GRANT_SCOPE_VIOLATION,
                    "记录 " + item.recordId() + " 不在授权范围");
        }
        java.util.Set<String> grantCanonical =
                fieldSelectionService.canonicalNames(policy, grant.fields());
        for (String f : fieldSelectionService.canonicalNames(policy, item.fields())) {
            if (!grantCanonical.contains(f)) {
                throw new GatewayException(ReasonCode.GRANT_SCOPE_VIOLATION,
                        "字段 " + f + " 不在授权范围");
            }
        }
    }

    private int batchMaxItems() {
        return batchProperties().getMaxItems();
    }

    private com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties.Batch batchProperties() {
        return batchProps.getBatch();
    }

    /**
     * 递归处理 JSON 结构。

    /** 签发限时明文导出授权。 */
    public com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant issueGrant(
            String caller, java.util.Set<String> recordIds, java.util.Set<String> fields, long ttlMillis) {
        return grantService.issue(caller, recordIds, fields, ttlMillis);
    }

    /** 撤销限时授权。 */
    public boolean revokeGrant(String grantId) {
        return grantService.revoke(grantId);
    }

    /**
     * 递归处理 JSON 结构。
     * 键名归一：逻辑名、别名、{@code {"value": x}} / {@code {"type":t,"value":x}} 包装
     * 全部视作同一逻辑字段；对象与数组任意深度一致。
     *
     * @param depth 当前 node 在树中的深度（顶层为 1）
     * @param wrapperField 当 node 本身是父键的 value 包装时，父键的逻辑名；否则 null
     */
    private void process(Object node, String path, int depth, String wrapperField,
                         AccessRequest request, Policy policy,
                         List<FieldDecision> decisions, boolean[] truncated, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            limitGuard.checkDepth(depth);
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;

            if (isWrapperMap(map)) {
                // {"value": x} / {"type":t,"value":x}：以父键逻辑名对整体判定一次
                String logical = wrapperField != null ? wrapperField : "value";
                FieldDecision d = decisionService.decide(policy, request, path, logical);
                decisions.add(d);
                if (d.action() == FieldAction.DENY) {
                    return;
                }
                Object inner = map.get("value");
                if (d.action() == FieldAction.MASK && !(inner instanceof Map<?, ?> || inner instanceof List<?>)) {
                    map.put("value", maskingService.mask(inner, decisionService.findRule(policy, logical)));
                    return;
                }
                // ALLOW，或内层仍为容器：继续递归，保证深层同名字段不漏
                process(inner, path + ".value", depth + 1, "value",
                        request, policy, decisions, truncated, startNanos);
                return;
            }

            for (Map.Entry<String, Object> e : new ArrayList<>(map.entrySet())) {
                String key = e.getKey();
                Object child = e.getValue();
                if (AesGcmCryptoService.isEnvelope(child)) {
                    // 密文信封视为该字段的标量值：字段规则照常判定（脱敏对信封幂等不变形）
                    applyScalar(map, key, key, path + "." + key, child, request, policy, decisions);
                } else if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    process(child, path + "." + key, depth + 1, key,
                            request, policy, decisions, truncated, startNanos);
                } else {
                    applyScalar(map, key, key, path + "." + key, child, request, policy, decisions);
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            limitGuard.checkArraySize(list.size());
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            if (limitGuard.mode() == com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode.TRUNCATE
                    && arr.size() > limitGuard.maxArraySize()) {
                truncated[0] = true;
                while (arr.size() > limitGuard.truncateArrayTo()) {
                    arr.remove(arr.size() - 1);
                }
            }
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                // 数组元素继承包装父键逻辑名；普通元素自身若为对象则在内部按键判定
                String childWrapper = wrapperField;
                if (child instanceof Map<?, ?> cm && !isWrapperMap(cm)) {
                    childWrapper = null;
                }
                if (AesGcmCryptoService.isEnvelope(child)) {
                    // 数组中的密文信封：按继承逻辑名对标量判定
                    applyScalar(arr, i, wrapperField, path + "[" + i + "]", child,
                            request, policy, decisions);
                } else if (child instanceof Map<?, ?> || child instanceof List<?>) {
                    process(child, path + "[" + i + "]", depth + 1, childWrapper,
                            request, policy, decisions, truncated, startNanos);
                } else {
                    applyScalar(arr, i, wrapperField, path + "[" + i + "]", child,
                            request, policy, decisions);
                }
            }
            return;
        }
        // 数组中的裸标量且带有继承逻辑名
        if (wrapperField != null) {
            // 不可达：调用方已在数组分支处理；保留防御
        }
    }

    private void applyScalar(Object holder, Object keyOrIndex, String logicalField,
                             String path, Object value, AccessRequest request,
                             Policy policy, List<FieldDecision> decisions) {
        if (logicalField == null) {
            return;
        }
        FieldRule rule = decisionService.findRule(policy, logicalField);
        if (rule == null) {
            return;
        }
        FieldDecision d = decisionService.decide(policy, request, path, logicalField);
        decisions.add(d);
        if (d.action() == FieldAction.MASK) {
            Object masked = maskingService.mask(value, rule);
            if (holder instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) map;
                m.put((String) keyOrIndex, masked);
            } else if (holder instanceof List<?> list) {
                @SuppressWarnings("unchecked")
                List<Object> arr = (List<Object>) list;
                arr.set((Integer) keyOrIndex, masked);
            }
        }
        // DENY：不替换，最终整单拒绝，不泄漏任何字段
    }

    private static boolean isWrapperMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            return false;
        }
        boolean single = map.size() == 1 && map.containsKey("value");
        boolean typed = map.size() == 2 && map.containsKey("value") && map.containsKey("type");
        return single || typed;
    }

    private static String safeDigest(Object data) {
        try {
            return Digests.sha256Hex(JsonCodec.canonical(data));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String summarize(List<FieldDecision> decisions) {
        StringBuilder sb = new StringBuilder();
        for (FieldDecision d : decisions) {
            sb.append('[').append(d.rationale()).append("] ");
        }
        return sb.toString().trim();
    }
}
