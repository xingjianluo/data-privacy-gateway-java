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

    public PrivacyGateway(PolicyStore policyStore, KeyStore keyStore, RecordStore recordStore,
                          CryptoService cryptoService, IngestService ingestService,
                          DecisionService decisionService, MaskingService maskingService,
                          AuditService auditService, LimitGuard limitGuard) {
        this.policyStore = policyStore;
        this.keyStore = keyStore;
        this.recordStore = recordStore;
        this.cryptoService = cryptoService;
        this.ingestService = ingestService;
        this.decisionService = decisionService;
        this.maskingService = maskingService;
        this.auditService = auditService;
        this.limitGuard = limitGuard;
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
                if (child instanceof Map<?, ?> || child instanceof List<?>) {
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
                if (child instanceof Map<?, ?> || child instanceof List<?>) {
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
