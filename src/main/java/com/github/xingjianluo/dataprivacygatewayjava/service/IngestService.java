package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldSpec;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestReport;
import com.github.xingjianluo.dataprivacygatewayjava.model.JsonType;
import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
import com.github.xingjianluo.dataprivacygatewayjava.model.NormalizedRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.RecordSchema;
import com.github.xingjianluo.dataprivacygatewayjava.store.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.util.JsonCodec;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 多来源接入与归一。
 * 失败原则：任何字段缺失（必填）、类型不符、超规模都显式拒绝，整单不落库、不留部分状态，
 * 每个违规字段给出独立且可区分的 {@link ReasonCode}，绝不静默丢弃。
 */
@Service
public class IngestService {

    private static final String WRAPPER_KEY = "value";

    private final RecordStore recordStore;
    private final GatewayProperties properties;
    private final AuditService auditService;

    public IngestService(RecordStore recordStore, GatewayProperties properties, AuditService auditService) {
        this.recordStore = recordStore;
        this.properties = properties;
        this.auditService = auditService;
    }

    public IngestReport ingest(String source, String recordId, Map<String, Object> raw, RecordSchema schema) {
        long start = System.nanoTime();
        if (recordId == null || recordId.isBlank()) {
            return reject(source, recordId, Map.of("$", ReasonCode.BAD_REQUEST),
                    ReasonCode.BAD_REQUEST, "recordId 必填", null);
        }
        if (raw == null) {
            return reject(source, recordId, Map.of("$", ReasonCode.BAD_REQUEST),
                    ReasonCode.BAD_REQUEST, "请求体为空", null);
        }
        String inputDigest = digestOf(raw);

        // 1) 整体规模硬上限：任何模式下都拒绝（截断无法保证记录语义完整）
        int bytes = JsonCodec.estimatedBytes(raw);
        if (bytes > properties.getLimits().getMaxRecordBytes()) {
            return reject(source, recordId, Map.of("$", ReasonCode.REJECT_SIZE_EXCEEDED),
                    ReasonCode.REJECT_SIZE_EXCEEDED,
                    "记录 " + bytes + " 字节超过上限 " + properties.getLimits().getMaxRecordBytes(),
                    inputDigest);
        }

        // 2) 深拷贝后在副本上做结构归一/校验，原始入参不被修改
        Object copied = JsonCodec.deepCopy(raw);
        if (!(copied instanceof Map<?, ?>)) {
            return reject(source, recordId, Map.of("$", ReasonCode.REJECT_TYPE_MISMATCH),
                    ReasonCode.REJECT_TYPE_MISMATCH, "顶层必须是 JSON 对象", inputDigest);
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) copied;

        Map<String, ReasonCode> violations = new LinkedHashMap<>();
        boolean[] truncated = {false};
        walk(data, 1, "$", violations, truncated);

        // 3) 顶层声明字段：缺失 / 类型不符（兼容 {"value": ...} 包装形式）
        if (schema != null) {
            for (FieldSpec spec : schema.fields()) {
                Object value = resolveWrapper(data.get(spec.name()));
                if (value == null) {
                    if (spec.required()) {
                        violations.put(spec.name(), ReasonCode.REJECT_MISSING_FIELD);
                    }
                    continue;
                }
                if (!matchesType(value, spec.type())) {
                    violations.put(spec.name(), ReasonCode.REJECT_TYPE_MISMATCH);
                }
            }
        }

        // 4) 耗时上限
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        if (elapsedMs > properties.getLimits().getMaxElapsedMillis()) {
            violations.put("$", ReasonCode.REQUEST_TIMEOUT);
        }

        if (!violations.isEmpty()) {
            ReasonCode first = violations.values().iterator().next();
            return reject(source, recordId, violations, first,
                    "接入被拒绝，违规 " + violations.size() + " 项：" + violations, inputDigest);
        }

        NormalizedRecord record = new NormalizedRecord(
                recordId, source, System.currentTimeMillis(), data, List.of());
        recordStore.put(record);

        ReasonCode reason = truncated[0] ? ReasonCode.TRUNCATED_BY_LIMIT : ReasonCode.INGEST_OK;
        auditService.record(source, "INGEST", recordId, reason, null, null, inputDigest,
                "接入成功" + (truncated[0] ? "（按截断策略裁掉超限部分）" : ""),
                Map.of("bytes", String.valueOf(bytes)));
        return new IngestReport(true, recordId, source, Map.of(), reason,
                truncated[0] ? "已接入，超限部分按策略截断" : "已接入");
    }

    private IngestReport reject(String source, String recordId, Map<String, ReasonCode> violations,
                                ReasonCode reason, String message, String inputDigest) {
        // 拒绝同样审计；审计失败不改变拒绝结论
        auditService.record(source, "INGEST", recordId, reason, null, null, inputDigest,
                "接入拒绝：" + message, Map.of("violations", violations.toString()));
        return new IngestReport(false, recordId, source,
                Map.copyOf(violations), reason, message);
    }

    /** 递归结构校验；TRUNCATE 模式就地裁掉过深子树与超长数组，返回处理后的值。 */
    private Object walk(Object value, int depth, String path,
                        Map<String, ReasonCode> violations, boolean[] truncated) {
        if (value instanceof Map<?, ?> map) {
            // 本容器自身深度：超出 maxDepth 的容器不允许出现（其内部叶子也视为过深）
            if (depth > properties.getLimits().getMaxDepth()) {
                if (properties.getLimits().getMode() == LimitMode.REJECT) {
                    violations.put(path, ReasonCode.REJECT_DEPTH_EXCEEDED);
                } else {
                    truncated[0] = true;
                    return null;
                }
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> obj = (Map<String, Object>) map;
            for (Map.Entry<String, Object> e : new ArrayList<>(obj.entrySet())) {
                int childDepth = depth + 1;
                boolean childContainer = e.getValue() instanceof Map<?, ?> || e.getValue() instanceof List<?>;
                if (childDepth > properties.getLimits().getMaxDepth()) {
                    if (properties.getLimits().getMode() == LimitMode.REJECT) {
                        violations.put(path + "." + e.getKey(), ReasonCode.REJECT_DEPTH_EXCEEDED);
                        continue;
                    }
                    truncated[0] = true;
                    obj.put(e.getKey(), childContainer ? null : null);
                    continue;
                }
                Object child = walk(e.getValue(), childDepth, path + "." + e.getKey(), violations, truncated);
                if (child != e.getValue()) {
                    obj.put(e.getKey(), child);
                }
            }
            return obj;
        }
        if (value instanceof List<?> list) {
            int max = properties.getLimits().getMaxArraySize();
            List<Object> arr = new ArrayList<>(list.size() + 1);
            if (list.size() > max && properties.getLimits().getMode() == LimitMode.REJECT) {
                violations.put(path, ReasonCode.REJECT_ARRAY_TOO_LARGE);
            }
            int limit = list.size();
            if (list.size() > max && properties.getLimits().getMode() == LimitMode.TRUNCATE) {
                limit = Math.min(list.size(), properties.getLimits().getTruncateArrayTo());
                truncated[0] = true;
            }
            for (int i = 0; i < limit; i++) {
                arr.add(walk(list.get(i), depth + 1, path + "[" + i + "]", violations, truncated));
            }
            return arr;
        }
        if (value instanceof String s && s.length() > properties.getLimits().getMaxStringLength()) {
            violations.put(path, ReasonCode.REJECT_STRING_TOO_LONG);
        }
        return value;
    }

    /** 兼容 {"value": x} 的单键包装；也兼容 {"type":..,"value":x} 双键包装。 */
    static Object resolveWrapper(Object value) {
        if (value instanceof Map<?, ?> map && map.containsKey(WRAPPER_KEY)
                && (map.size() == 1 || (map.size() == 2 && map.containsKey("type")))) {
            return map.get(WRAPPER_KEY);
        }
        return value;
    }

    static boolean matchesType(Object value, JsonType type) {
        return switch (type) {
            case STRING -> value instanceof String;
            case NUMBER -> value instanceof Number;
            case BOOLEAN -> value instanceof Boolean;
            case OBJECT -> value instanceof Map<?, ?>;
            case ARRAY -> value instanceof List<?>;
        };
    }

    private static String digestOf(Map<String, Object> raw) {
        try {
            return com.github.xingjianluo.dataprivacygatewayjava.util.Digests
                    .sha256Hex(JsonCodec.canonical(raw));
        } catch (RuntimeException e) {
            return null;
        }
    }
}
