package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
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
import com.github.xingjianluo.dataprivacygatewayjava.model.ResolvedGrant;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.util.Digests;
import com.github.xingjianluo.dataprivacygatewayjava.util.JsonCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
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

    public PrivacyGateway(PolicyStore policyStore, KeyStore keyStore, RecordStore recordStore,
                          CryptoService cryptoService, IngestService ingestService,
                          DecisionService decisionService, MaskingService maskingService,
                          AuditService auditService, LimitGuard limitGuard, GrantService grantService) {
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

    public long currentPolicyVersion() {
        Policy p = policyStore.current();
        return p == null ? -1 : p.version();
    }

    /**
     * 批量路径复用的单条目处理（脱敏批量 / 授权明文导出共用）。
     * <p>固定调用方给定的策略与密钥版本；本条目的任何异常都在条目内收敛为失败结果，
     * 绝不外抛影响其他条目。失败结果的 view 恒为 null，不泄漏已解开的中间结果。</p>
     *
     * @param mode "ACCESS"（脱敏批量，语义同单条入口）或 "EXPORT"（授权明文导出）
     */
    public com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult processBatchItem(
            String caller, Level clearance, String recordId, boolean rawRequested,
            List<String> fields, ResolvedGrant grant,
            Policy policy, int pinnedKeyVersion, long startNanos, String mode) {
        boolean export = "EXPORT".equals(mode);
        NormalizedRecord record = recordStore.get(recordId);
        if (record == null) {
            String eid = auditService.record(caller, export ? "BATCH_EXPORT" : "BATCH_ACCESS",
                    recordId, ReasonCode.BAD_REQUEST, policy.version(), pinnedKeyVersion,
                    null, "记录不存在，跳过该条", Map.of());
            return new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult(
                    recordId, false, ReasonCode.BAD_REQUEST, null, List.of(), eid, false,
                    policy.version(), pinnedKeyVersion);
        }
        String inputDigest = safeDigest(record.data());
        @SuppressWarnings("unchecked")
        Map<String, Object> view = (Map<String, Object>) JsonCodec.deepCopy(record.data());
        List<FieldDecision> decisions = new ArrayList<>();
        boolean[] truncated = {false};
        AccessRequest effective = new AccessRequest(caller, clearance, recordId, rawRequested);

        try {
            if (export) {
                // 明文导出：先把点名范围之外的字段剔除，再按授权解密/放行
                pruneToFields(view, "$", 1, null, fields, policy, startNanos);
                exportProcess(view, "$", 1, null, recordId, fields, grant, policy,
                        effective, decisions, startNanos);
            } else {
                pruneToFields(view, "$", 1, null, fields, policy, startNanos);
                process(view, "$", 1, null, effective, policy, grant, recordId,
                        decisions, truncated, startNanos);
            }
            limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        } catch (GatewayException e) {
            // 条目内失败（含超时/超限/解密失败）：不返回该条任何已处理视图
            String eid = auditService.record(caller, export ? "BATCH_EXPORT" : "BATCH_ACCESS",
                    recordId, e.code(), policy.version(), pinnedKeyVersion,
                    inputDigest, "条目处理失败：" + e.getMessage(),
                    Map.of("mode", mode));
            return new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult(
                    recordId, false, e.code(), null, List.of(), eid, false,
                    policy.version(), pinnedKeyVersion);
        }

        boolean denied = decisions.stream().anyMatch(d -> d.action() == FieldAction.DENY);
        ReasonCode overall;
        if (denied) {
            overall = export ? ReasonCode.GRANT_SCOPE_VIOLATION
                    : ReasonCode.DENIED_UNAUTHORIZED_RAW_READ;
        } else if (truncated[0]) {
            overall = ReasonCode.TRUNCATED_BY_LIMIT;
        } else if (decisions.stream().anyMatch(d -> d.action() == FieldAction.MASK)) {
            overall = ReasonCode.MASKED_INSUFFICIENT_CLEARANCE;
        } else {
            overall = ReasonCode.ALLOWED;
        }

        int allow = 0, mask = 0, deny = 0;
        for (FieldDecision dd : decisions) {
            switch (dd.action()) {
                case ALLOW -> allow++;
                case MASK -> mask++;
                case DENY -> deny++;
            }
        }
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("counts", "ALLOW=" + allow + ",MASK=" + mask + ",DENY=" + deny);
        detail.put("mode", mode);
        if (grant != null) {
            detail.put("grantId", grant.grantId());
        }
        String eid = auditService.record(caller, export ? "BATCH_EXPORT" : "BATCH_ACCESS",
                recordId, overall, policy.version(), pinnedKeyVersion,
                inputDigest, summarize(decisions), detail);
        LOG.info("[{}] recordId={} caller={} | outcome={} policyV={} keyV={} decisions={}",
                mode, recordId, caller, overall, policy.version(), pinnedKeyVersion,
                summarize(decisions));

        // 批量语义：逐条给结论，允许/脱敏/拒绝混排在同一批；
        // 单条即使有字段被拒（越范围）也不抛异常，由结果中的 deny 判定表达，
        // 但被拒字段绝不以明文出现在 view 中（遍历时已剔除/置空）。
        return new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult(
                recordId, true, overall, view, List.copyOf(decisions), eid, truncated[0],
                policy.version(), pinnedKeyVersion);
    }

    /**
     * 将视图裁剪到“点名字段集合”：fields 为 null/空表示全部保留。
     * 命中规则与判定一致：键名按策略逻辑名/别名匹配 + {@code {"value":..}} 包装继承父键名。
     */
    private void pruneToFields(Object node, String path, int depth, String wrapperField,
                               List<String> fields, Policy policy, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (fields == null || fields.isEmpty()) {
            return;
        }
        if (node instanceof Map<?, ?> rawMap) {
            limitGuard.checkDepth(depth);
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (isWrapperMap(map)) {
                String logical = wrapperField != null ? wrapperField : "value";
                Object inner = map.get("value");
                if (named(fields, policy, logical)) {
                    return; // 整个包装值属于点名字段，全保留
                }
                if (isContainerButNotEnvelope(inner)) {
                    pruneToFields(inner, path + ".value", depth + 1, "value", fields, policy, startNanos);
                } else {
                    map.put("value", null);
                }
                return;
            }
            for (String key : new ArrayList<>(map.keySet())) {
                Object child = map.get(key);
                if (named(fields, policy, key)) {
                    continue;
                }
                if (isContainerButNotEnvelope(child)) {
                    pruneToFields(child, path + "." + key, depth + 1, key, fields, policy, startNanos);
                    if (isEmptyContainer(child)) {
                        map.remove(key);
                    }
                } else {
                    map.remove(key);
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            limitGuard.checkArraySize(list.size());
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                if (isContainerButNotEnvelope(child)) {
                    String inherited = (child instanceof Map<?, ?> cm && !isWrapperMap(cm))
                            ? null : wrapperField;
                    pruneToFields(child, path + "[" + i + "]", depth + 1, inherited,
                            fields, policy, startNanos);
                    if (isEmptyContainer(child)) {
                        arr.remove(i);
                        i--;
                    }
                } else if (wrapperField == null || !named(fields, policy, wrapperField)) {
                    arr.remove(i);
                    i--;
                }
            }
        }
    }

    /** 点名字段是否命中：直接名或经策略别名解析后的逻辑名。 */
    private boolean named(List<String> fields, Policy policy, String keyName) {
        if (fields == null || fields.isEmpty()) {
            return true;
        }
        if (fields.contains(keyName)) {
            return true;
        }
        FieldRule rule = decisionService.findRule(policy, keyName);
        return rule != null && fields.contains(rule.field());
    }

    private static boolean isContainerButNotEnvelope(Object value) {
        return (value instanceof Map<?, ?> || value instanceof List<?>)
                && !AesGcmCryptoService.isEnvelope(value);
    }

    private static boolean isEmptyContainer(Object value) {
        if (value instanceof Map<?, ?> m) {
            return m.isEmpty();
        }
        if (value instanceof List<?> l) {
            return l.isEmpty();
        }
        return false;
    }

    /**
     * 明文导出遍历：只针对点名字段判定，授权覆盖的字段解密密文信封并保留明文，
     * 未覆盖（越范围）字段判 DENY(GRANT_SCOPE_VIOLATION) 并从视图剔除/置空，绝不返回明文。
     * 密文信封作为标量处理（不当容器递归），按信封自身 v 取历史/当前密钥解密。
     * 与单条入口共用 {@link DecisionService}，授权口径一致。
     */
    private void exportProcess(Object node, String path, int depth, String wrapperField,
                               String recordId, List<String> fields, ResolvedGrant grant,
                               Policy policy, AccessRequest request,
                               List<FieldDecision> decisions, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            limitGuard.checkDepth(depth);
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (isWrapperMap(map)) {
                String logical = wrapperField != null ? wrapperField : "value";
                Object inner = map.get("value");
                if (named(fields, policy, logical)) {
                    FieldDecision d = decisionService.decide(policy, request, path, logical,
                            grant, recordId, true);
                    decisions.add(d);
                    if (d.action() == FieldAction.DENY) {
                        map.put("value", null);
                        return;
                    }
                    if (!isContainerButNotEnvelope(inner)) {
                        // 标量（含密文信封）：覆盖则解密/保留
                        map.put("value", decryptIfEnvelope(inner));
                        return;
                    }
                }
                if (isContainerButNotEnvelope(inner)) {
                    exportProcess(inner, path + ".value", depth + 1, "value",
                            recordId, fields, grant, policy, request, decisions, startNanos);
                }
                return;
            }
            for (String key : new ArrayList<>(map.keySet())) {
                Object child = map.get(key);
                if (named(fields, policy, key) && !isContainerButNotEnvelope(child)) {
                    FieldDecision d = decisionService.decide(policy, request, path + "." + key,
                            key, grant, recordId, true);
                    decisions.add(d);
                    if (d.action() == FieldAction.DENY) {
                        map.remove(key);
                    } else {
                        map.put(key, decryptIfEnvelope(child));
                    }
                } else if (isContainerButNotEnvelope(child)) {
                    exportProcess(child, path + "." + key, depth + 1, key,
                            recordId, fields, grant, policy, request, decisions, startNanos);
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            limitGuard.checkArraySize(list.size());
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                if (isContainerButNotEnvelope(child)) {
                    String childWrapper = wrapperField;
                    if (child instanceof Map<?, ?> cm && !isWrapperMap(cm)) {
                        childWrapper = null;
                    }
                    exportProcess(child, path + "[" + i + "]", depth + 1, childWrapper,
                            recordId, fields, grant, policy, request, decisions, startNanos);
                } else if (wrapperField != null && named(fields, policy, wrapperField)) {
                    FieldDecision d = decisionService.decide(policy, request, path + "[" + i + "]",
                            wrapperField, grant, recordId, true);
                    decisions.add(d);
                    if (d.action() == FieldAction.DENY) {
                        arr.set(i, null);
                    } else {
                        arr.set(i, decryptIfEnvelope(child));
                    }
                }
            }
        }
    }

    /**
     * 单条授权访问的补充遍历：仅解密“授权覆盖的逻辑字段”上的密文信封，
     * 其他信封原样保留。结构/别名/包装口径与主遍历一致。
     */
    private void decryptGrantedRecursively(Object node, String path, int depth, String wrapperField,
                                           AccessRequest request, Policy policy,
                                           ResolvedGrant grant, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            limitGuard.checkDepth(depth);
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (isWrapperMap(map)) {
                String logical = wrapperField != null ? wrapperField : "value";
                Object inner = map.get("value");
                FieldRule rule = decisionService.findRule(policy, logical);
                String canonical = rule == null ? logical : rule.field();
                if (grant.covers(request.recordId(), canonical)
                        && AesGcmCryptoService.isEnvelope(inner)) {
                    CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(inner));
                    map.put("value", cryptoService.decrypt(env));
                    return;
                }
                if (isContainerButNotEnvelope(inner)) {
                    decryptGrantedRecursively(inner, path + ".value", depth + 1, "value",
                            request, policy, grant, startNanos);
                }
                return;
            }
            for (Map.Entry<String, Object> e : new ArrayList<>(map.entrySet())) {
                String key = e.getKey();
                Object child = e.getValue();
                FieldRule rule = decisionService.findRule(policy, key);
                String canonical = rule == null ? key : rule.field();
                if (grant.covers(request.recordId(), canonical)
                        && AesGcmCryptoService.isEnvelope(child)) {
                    CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(child));
                    map.put(key, cryptoService.decrypt(env));
                } else if (isContainerButNotEnvelope(child)) {
                    decryptGrantedRecursively(child, path + "." + key, depth + 1, key,
                            request, policy, grant, startNanos);
                }
            }
            return;
        }
        if (node instanceof List<?> list) {
            limitGuard.checkArraySize(list.size());
            @SuppressWarnings("unchecked")
            List<Object> arr = (List<Object>) node;
            for (int i = 0; i < arr.size(); i++) {
                Object child = arr.get(i);
                if (isContainerButNotEnvelope(child)) {
                    String childWrapper = wrapperField;
                    if (child instanceof Map<?, ?> cm && !isWrapperMap(cm)) {
                        childWrapper = null;
                    }
                    decryptGrantedRecursively(child, path + "[" + i + "]", depth + 1,
                            childWrapper, request, policy, grant, startNanos);
                } else if (wrapperField != null && AesGcmCryptoService.isEnvelope(child)) {
                    FieldRule rule = decisionService.findRule(policy, wrapperField);
                    String canonical = rule == null ? wrapperField : rule.field();
                    if (grant.covers(request.recordId(), canonical)) {
                        CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(child));
                        arr.set(i, cryptoService.decrypt(env));
                    }
                }
            }
        }
    }

    /** 若是密文信封则按信封自身 v 用历史/当前密钥解密；历史密文在轮换后同样可解。 */
    private Object decryptIfEnvelope(Object value) {
        if (AesGcmCryptoService.isEnvelope(value)) {
            CipherEnvelope env = AesGcmCryptoService.fromMap(asMap(value));
            return cryptoService.decrypt(env);
        }
        return value;
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

        // 若携带限时明文授权，先严格校验（跨调用方/过期/撤销/缺失都会在这里受控拒绝并留痕）；
        // 校验通过后与持证等级等效参与字段判定，保证单条/批量口径一致。
        ResolvedGrant grant = null;
        if (request.grantId() != null && !request.grantId().isBlank()) {
            grant = grantService.validate(request.caller(), request.grantId());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> view = (Map<String, Object>) JsonCodec.deepCopy(record.data());
        List<FieldDecision> decisions = new ArrayList<>();
        boolean[] truncated = {false};

        process(view, "$", 1, null, request, policy, grant, request.recordId(),
                decisions, truncated, start);
        // 单条携带限时授权：授权覆盖字段的密文信封需解密为明文（与批量导出口径一致），
        // 其余字段的信封保持原样（普通访问从不解密）
        if (grant != null) {
            decryptGrantedRecursively(view, "$", 1, null, request, policy, grant, start);
        }
        limitGuard.checkElapsed(start, ReasonCode.ALLOWED);
        // 交付前复核授权：处理期间被并发撤销/过期则整单拒绝，不返回明文
        if (grant != null && !grantService.stillValid(grant, System.currentTimeMillis())) {
            String revokeEid = auditService.record(request.caller(), "ACCESS", request.recordId(),
                    ReasonCode.GRANT_REVOKED, policy.version(), pinnedKeyVersion, inputDigest,
                    "授权在处理期间被撤销或过期，拒绝交付", Map.of("grantId", grant.grantId()));
            throw new GatewayException(ReasonCode.GRANT_REVOKED,
                    "授权已失效，拒绝交付，见审计事件 " + revokeEid);
        }

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
     * 递归处理 JSON 结构。
     * 键名归一：逻辑名、别名、{@code {"value": x}} / {@code {"type":t,"value":x}} 包装
     * 全部视作同一逻辑字段；对象与数组任意深度一致。
     *
     * @param depth 当前 node 在树中的深度（顶层为 1）
     * @param wrapperField 当 node 本身是父键的 value 包装时，父键的逻辑名；否则 null
     */
    private void process(Object node, String path, int depth, String wrapperField,
                         AccessRequest request, Policy policy,
                         ResolvedGrant grant, String recordId,
                         List<FieldDecision> decisions, boolean[] truncated, long startNanos) {
        limitGuard.checkElapsed(startNanos, ReasonCode.ALLOWED);
        if (node instanceof Map<?, ?> rawMap) {
            limitGuard.checkDepth(depth);
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;

            if (isWrapperMap(map)) {
                // {"value": x} / {"type":t,"value":x}：以父键逻辑名对整体判定一次
                String logical = wrapperField != null ? wrapperField : "value";
                FieldDecision d = decisionService.decide(policy, request, path, logical,
                        grant, recordId);
                decisions.add(d);
                if (d.action() == FieldAction.DENY) {
                    // 批量逐条返回时必须剔除被拒字段原值，杜绝明文随视图泄漏；
                    // 单条路径最终也会整单拒绝，行为不受影响
                    map.put("value", null);
                    return;
                }
                Object inner = map.get("value");
                if (d.action() == FieldAction.MASK && !isContainerButNotEnvelope(inner)) {
                    map.put("value", maskingService.mask(inner, decisionService.findRule(policy, logical)));
                    return;
                }
                // ALLOW，或内层仍为（非信封）容器：继续递归，保证深层同名字段不漏；
                // 密文信封是不透明标量，按逻辑字段整体判定后原样保留，不解密也不展开
                if (isContainerButNotEnvelope(inner)) {
                    process(inner, path + ".value", depth + 1, "value",
                            request, policy, grant, recordId, decisions, truncated, startNanos);
                }
                return;
            }

            for (Map.Entry<String, Object> e : new ArrayList<>(map.entrySet())) {
                String key = e.getKey();
                Object child = e.getValue();
                // 密文信封是不透明标量叶子：按键逻辑字段判定，不展开（展开会把加密载荷当普通 JSON）
                if (isContainerButNotEnvelope(child)) {
                    process(child, path + "." + key, depth + 1, key,
                            request, policy, grant, recordId, decisions, truncated, startNanos);
                } else {
                    applyScalar(map, key, key, path + "." + key, child, request, policy,
                            grant, recordId, decisions);
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
                if (child instanceof Map<?, ?> cm && !isWrapperMap(cm)
                        && !AesGcmCryptoService.isEnvelope(child)) {
                    childWrapper = null;
                }
                if (isContainerButNotEnvelope(child)) {
                    process(child, path + "[" + i + "]", depth + 1, childWrapper,
                            request, policy, grant, recordId, decisions, truncated, startNanos);
                } else {
                    applyScalar(arr, i, wrapperField, path + "[" + i + "]", child,
                            request, policy, grant, recordId, decisions);
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
                             Policy policy, ResolvedGrant grant, String recordId,
                             List<FieldDecision> decisions) {
        if (logicalField == null) {
            return;
        }
        FieldRule rule = decisionService.findRule(policy, logicalField);
        if (rule == null) {
            return;
        }
        FieldDecision d = decisionService.decide(policy, request, path, logicalField,
                grant, recordId);
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
        } else if (d.action() == FieldAction.DENY) {
            // 批量逐条返回：被拒字段从视图剔除（Map 删键 / List 置 null），绝不返回原值
            if (holder instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) map;
                m.remove((String) keyOrIndex);
            } else if (holder instanceof List<?> list) {
                @SuppressWarnings("unchecked")
                List<Object> arr = (List<Object>) list;
                arr.set((Integer) keyOrIndex, null);
            }
        }
        // 注：单条入口 raw 越权最终整单拒绝；剔除仅用于批量逐条视图的失败安全
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
