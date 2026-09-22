package com.github.xingjianluo.dataprivacygatewayjava.access;

import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditOutcome;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditService;
import com.github.xingjianluo.dataprivacygatewayjava.config.DeadlineExceededException;
import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.config.LimitExceededException;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoException;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyRing;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskingService;
import com.github.xingjianluo.dataprivacygatewayjava.model.CallerIdentity;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataNode;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldMeta;
import com.github.xingjianluo.dataprivacygatewayjava.model.Nodes;
import com.github.xingjianluo.dataprivacygatewayjava.model.NormalizedRecord;
import com.github.xingjianluo.dataprivacygatewayjava.policy.AccessPolicy;
import com.github.xingjianluo.dataprivacygatewayjava.policy.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.policy.PolicyStore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 访问判定网关。
 * <p>一次读取在入口处同时抓取 {@link AccessPolicy} 与 {@link KeyRing} 两个不可变快照，
 * 随后所有字段判定、解密都在这对确定版本上完成：并发更新策略或轮换密钥时，
 * 单次结论不会混用新旧版本，也不会出现"密文已按新版本、依据却记旧版本"。
 * <p>判定规则：
 * <ul>
 *   <li>权限足够：密文先解密返回明文（NORMAL / RAW 一致）。</li>
 *   <li>权限不足 + NORMAL：返回脱敏值（不是报错）；密文不先解密，直接脱敏为固定标记，
 *       不泄漏任何明文信息。</li>
 *   <li>权限不足 + RAW：拒绝原始读取（DENIED），逐字段留下判定依据。</li>
 *   <li>规模超限：整体拒绝，不返回部分处理结果。</li>
 *   <li>耗时超限：立即中止，返回失败结果，已解密的中间值不写入结果。</li>
 *   <li>解密失败：按密钥版本缺失 / 版本不匹配等原因记录 FAILED，底层异常不透出。</li>
 * </ul>
 */
public class AccessGateway {

    /** 拒绝占位：不含原文，用于被拒绝叶子，保证"不得读到原始值"。 */
    public static final String DENIED_MARKER = "[DENIED]";
    /** 失败占位：不含原文与底层异常细节。 */
    public static final String FAILED_MARKER = "[FAILED]";

    private final RecordStore recordStore;
    private final PolicyStore policyStore;
    private final CryptoService cryptoService;
    private final MaskingService maskingService;
    private final AuditService auditService;
    private final GatewayProperties properties;

    public AccessGateway(RecordStore recordStore, PolicyStore policyStore, CryptoService cryptoService,
                         MaskingService maskingService, AuditService auditService,
                         GatewayProperties properties) {
        this.recordStore = recordStore;
        this.policyStore = policyStore;
        this.cryptoService = cryptoService;
        this.maskingService = maskingService;
        this.auditService = auditService;
        this.properties = properties;
    }

    public AccessResult access(CallerIdentity caller, String recordId, AccessMode mode) {
        long deadlineNanos = System.nanoTime() + properties.getProcessingTimeoutMillis() * 1_000_000L;

        if (caller == null || caller.callerId() == null || caller.callerId().isBlank()) {
            return failAndAudit(caller, recordId, null, null, "INVALID_CALLER",
                    "caller identity missing", 0, 0);
        }
        NormalizedRecord record = recordStore.get(recordId);
        if (record == null) {
            return failAndAudit(caller, recordId, null, null, "RECORD_NOT_FOUND",
                    "record does not exist", 0, 0);
        }

        // 入口一次性确定本次结论所基于的两个版本；解密与审计依据共用同一个 KeyRing 快照，
        // 杜绝"密文按新版本、依据记旧版本"的错配
        AccessPolicy policy = policyStore.current();
        KeyRing keyRing = cryptoService.currentRing();

        int leafCount = Nodes.countLeaves(record.root());
        if (leafCount > properties.getMaxLeavesPerResponse()) {
            AccessResult denied = new AccessResult(DecisionOutcome.DENIED, null, List.of(),
                    policy.version(), keyRing.currentVersion());
            audit(caller, recordId, AuditOutcome.DENY,
                    "LIMIT_EXCEEDED: " + leafCount + " leaves > " + properties.getMaxLeavesPerResponse(),
                    List.of(), null, policy, keyRing);
            return denied;
        }

        List<FieldDecision> decisions = new ArrayList<>();
        List<String> allPaths = new ArrayList<>();

        DataNode transformed;
        try {
            transformed = Nodes.mapLeaves(record.root(), (path, leaf) -> {
                checkDeadline(deadlineNanos, path);
                allPaths.add(path);
                FieldRule rule = resolveRule(policy.rules(), path, leaf);
                DataNode.Leaf out = decideLeaf(caller, mode, path, leaf, rule, policy, keyRing, decisions);
                return out;
            });
        } catch (DeadlineExceededException e) {
            // 立即中止：丢弃任何已构建的中间结果（含可能已解密的明文），只返回失败结论
            audit(caller, recordId, AuditOutcome.FAIL, "DEADLINE_EXCEEDED: " + e.getMessage(),
                    List.copyOf(decisions), null, policy, keyRing);
            return new AccessResult(DecisionOutcome.FAILED, null, List.copyOf(decisions),
                    policy.version(), keyRing.currentVersion());
        }

        DecisionOutcome overall = aggregate(decisions);
        DataNode.Obj resultRoot = overall == DecisionOutcome.FAILED
                ? null
                : (DataNode.Obj) transformed;

        AuditOutcome auditOutcome = switch (overall) {
            case ALLOWED -> AuditOutcome.ALLOW;
            case MASKED -> AuditOutcome.MASK;
            case DENIED -> AuditOutcome.DENY;
            case FAILED -> AuditOutcome.FAIL;
        };
        audit(caller, recordId, auditOutcome, overall.name(), List.copyOf(decisions),
                allPaths, policy, keyRing);
        return new AccessResult(overall, resultRoot, List.copyOf(decisions),
                policy.version(), keyRing.currentVersion());
    }

    private DataNode.Leaf decideLeaf(CallerIdentity caller, AccessMode mode, String path,
                                     DataNode.Leaf leaf, FieldRule rule,
                                     AccessPolicy policy, KeyRing keyRing,
                                     List<FieldDecision> decisions) {
        DataClassification required = rule.minClearance();
        boolean permitted = caller.canReadRaw(required);
        long pv = policy.version();
        int kv = keyRing.currentVersion();

        if (permitted) {
            if (leaf.meta().encrypted()) {
                try {
                    String plain = cryptoService.decrypt(leaf.value(), keyRing);
                    decisions.add(new FieldDecision(path, DecisionOutcome.ALLOWED,
                            "clearance>=required; decrypted with embedded key version", pv,
                            embeddedVersion(leaf.value())));
                    return new DataNode.Leaf(plain, FieldMeta.plain(leaf.meta().classification()));
                } catch (CryptoException e) {
                    // 底层异常不外泄：仅回传领域原因分类
                    decisions.add(new FieldDecision(path, DecisionOutcome.FAILED,
                            "CRYPTO:" + e.kind(), pv, safeEmbeddedVersion(leaf.value())));
                    return new DataNode.Leaf(FAILED_MARKER, FieldMeta.plain(leaf.meta().classification()));
                }
            }
            decisions.add(new FieldDecision(path, DecisionOutcome.ALLOWED,
                    "clearance>=required", pv, kv));
            return leaf;
        }

        // 权限不足
        if (mode == AccessMode.RAW) {
            // 越权读取原始值：拒绝，结果位置绝不放原文
            decisions.add(new FieldDecision(path, DecisionOutcome.DENIED,
                    "INSUFFICIENT_CLEARANCE: required " + required
                            + ", caller lacks it; raw read denied", pv, kv));
            return new DataNode.Leaf(DENIED_MARKER, FieldMeta.plain(leaf.meta().classification()));
        }

        // NORMAL：脱敏而非报错。
        // - 已脱敏值原样返回（幂等，不叠加变形）；
        // - 密文不先解密，直接给固定脱敏标记，杜绝明文中间泄漏；
        // - 普通明文按脱敏策略处理。
        String masked;
        if (leaf.meta().masked()) {
            masked = leaf.value();
        } else if (leaf.meta().encrypted()) {
            masked = MaskingService.MASK_MARKER;
        } else {
            masked = maskingService.mask(leaf.value());
        }
        decisions.add(new FieldDecision(path, DecisionOutcome.MASKED,
                "INSUFFICIENT_CLEARANCE: required " + required + ", masked instead of raw",
                pv, kv));
        return new DataNode.Leaf(masked, leaf.meta().asMasked());
    }

    private static DecisionOutcome aggregate(List<FieldDecision> decisions) {
        if (decisions.isEmpty()) {
            return DecisionOutcome.ALLOWED;
        }
        DecisionOutcome worst = DecisionOutcome.ALLOWED;
        for (FieldDecision d : decisions) {
            if (d.outcome().ordinal() > worst.ordinal()) {
                worst = d.outcome();
            }
        }
        return worst;
    }

    private static void checkDeadline(long deadlineNanos, String path) {
        if (System.nanoTime() > deadlineNanos) {
            throw new DeadlineExceededException("processing timed out at field " + path);
        }
    }

    private int embeddedVersion(String wire) {
        try {
            return com.github.xingjianluo.dataprivacygatewayjava.crypto.CipherToken.parse(wire).keyVersion();
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private int safeEmbeddedVersion(String wire) {
        return embeddedVersion(wire);
    }

    private void audit(CallerIdentity caller, String recordId, AuditOutcome outcome, String reason,
                       List<FieldDecision> basis, List<String> pathsForSummary,
                       AccessPolicy policy, KeyRing keyRing) {
        List<String> paths = pathsForSummary == null
                ? basis.stream().map(FieldDecision::path).distinct().sorted().toList()
                : pathsForSummary.stream().distinct().sorted().toList();
        String summary = auditService.summarize(
                caller == null ? "anonymous" : caller.callerId(), recordId, paths);
        auditService.recordAccess(caller, recordId, outcome, reason, summary, basis,
                policy.version(), keyRing.currentVersion());
    }

    private AccessResult failAndAudit(CallerIdentity caller, String recordId, DataNode.Obj data,
                                      List<FieldDecision> decisions, String reason, String detail,
                                      long policyVersion, int keyVersion) {
        AuditOutcome outcome = "RECORD_NOT_FOUND".equals(reason) || "INVALID_CALLER".equals(reason)
                ? AuditOutcome.FAIL : AuditOutcome.DENY;
        // 尽量取到当前版本用于依据；取不到则记 0，不影响结论
        long pv = policyVersion;
        int kv = keyVersion;
        try {
            pv = policyStore.current().version();
            kv = cryptoServiceCurrentVersion();
        } catch (RuntimeException ignored) {
            // 版本不可得时不阻断失败结论
        }
        List<FieldDecision> basis = decisions == null ? List.of() : decisions;
        String summary = auditService.summarize(
                caller == null ? "anonymous" : caller.callerId(), recordId, List.of());
        auditService.recordAccess(caller, recordId, outcome, reason + ":" + detail,
                summary, basis, pv, kv);
        return new AccessResult(DecisionOutcome.FAILED, data, basis, pv, kv);
    }

    private int cryptoServiceCurrentVersion() {
        return cryptoService.currentRing().currentVersion();
    }

    static FieldRule resolveRule(List<FieldRule> rules, String path, DataNode.Leaf leaf) {
        FieldRule wildcard = null;
        for (FieldRule rule : rules) {
            if (rule.fieldPath().equals(path)) {
                return rule;
            }
            if ("*".equals(rule.fieldPath())) {
                wildcard = rule;
            }
        }
        // 缺省规则：最低许可取"字段自身分类"与通配规则要求中的较高者，
        // 避免通配规则把高分类字段的要求意外降低
        DataClassification required = leaf.meta().classification();
        if (wildcard != null && wildcard.minClearance().level() > required.level()) {
            required = wildcard.minClearance();
        }
        boolean encrypt = wildcard != null && wildcard.encryptAtRest();
        return new FieldRule("*", required, encrypt);
    }
}
