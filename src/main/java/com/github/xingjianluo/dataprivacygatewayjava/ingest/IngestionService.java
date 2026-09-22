package com.github.xingjianluo.dataprivacygatewayjava.ingest;

import com.github.xingjianluo.dataprivacygatewayjava.config.LimitExceededException;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoException;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataNode;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldMeta;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestionResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.NormalizedRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.RejectionReason;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 多来源记录接入与归一。
 * <p>校验规则（全部违例一次性收集，绝不静默丢弃）：
 * <ul>
 *   <li>{@link RejectionReason#MALFORMED_RECORD}：来源未注册 / 载荷不是对象 / ID 缺失。</li>
 *   <li>{@link RejectionReason#MISSING_FIELD}：必填字段缺失或为 null。</li>
 *   <li>{@link RejectionReason#TYPE_MISMATCH}：实际结构与画像声明的 kind 不符。</li>
 *   <li>{@link RejectionReason#SIZE_LIMIT_EXCEEDED}：归一后节点数超上限或数组超长（按策略截断或拒绝）。</li>
 *   <li>{@link RejectionReason#PROCESSING_FAILURE}：落库加密等处理失败（不留半处理状态）。</li>
 * </ul>
 * 校验全部通过后才产出 {@link NormalizedRecord}；任何违例都返回拒绝结果，不部分落库。
 */
public class IngestionService {

    private final Map<String, SourceProfile> profiles;
    private final int maxNodesPerRecord;
    private final List<SourceAdapter> adapters = new ArrayList<>();
    private final CryptoService cryptoService;
    private final int maxArrayLength;
    private final boolean truncateOversizeArrays;

    public IngestionService(Map<String, SourceProfile> profiles, int maxNodesPerRecord) {
        this(profiles, maxNodesPerRecord, List.of(new JsonSourceAdapter()), null, 500, true);
    }

    public IngestionService(Map<String, SourceProfile> profiles, int maxNodesPerRecord,
                            List<SourceAdapter> adapters) {
        this(profiles, maxNodesPerRecord, adapters, null, 500, true);
    }

    public IngestionService(Map<String, SourceProfile> profiles, int maxNodesPerRecord,
                            List<SourceAdapter> adapters, CryptoService cryptoService,
                            int maxArrayLength, boolean truncateOversizeArrays) {
        this.profiles = Map.copyOf(profiles);
        this.maxNodesPerRecord = maxNodesPerRecord;
        this.adapters.addAll(adapters);
        this.cryptoService = cryptoService;
        this.maxArrayLength = maxArrayLength;
        this.truncateOversizeArrays = truncateOversizeArrays;
    }

    public void registerAdapter(SourceAdapter adapter) {
        adapters.add(adapter);
    }

    public IngestionResult ingest(SourceRecord record) {
        Map<String, RejectionReason> violations = new LinkedHashMap<>();
        if (record == null || record.source() == null) {
            return IngestionResult.reject(Map.of("(root)", RejectionReason.MALFORMED_RECORD));
        }
        SourceProfile profile = profiles.get(record.source());
        if (profile == null) {
            return IngestionResult.reject(Map.of("(source)",
                    RejectionReason.MALFORMED_RECORD));
        }

        Object payload = record.payload();
        for (SourceAdapter adapter : adapters) {
            if (adapter.supports(record.source())) {
                try {
                    payload = adapter.adapt(payload);
                } catch (RuntimeException e) {
                    // 适配器失败不静默：明确拒绝，不透出底层异常文本
                    violations.put("(adapter)", RejectionReason.MALFORMED_RECORD);
                    return IngestionResult.reject(violations);
                }
                break;
            }
        }
        if (!(payload instanceof Map<?, ?> rootMap)) {
            violations.put("(root)", RejectionReason.MALFORMED_RECORD);
            return IngestionResult.reject(violations);
        }

        String recordId = resolveId(profile, record.recordIdHint(), rootMap, violations);
        if (!violations.isEmpty()) {
            return IngestionResult.reject(violations);
        }

        // 必填字段存在性检查（数组透明：路径 a.b 命中任意数组元素内的 b 即算存在）；
        // 不在此提前返回——所有违例（缺失/类型/规模）必须一次性全部收集
        checkRequiredPresent(profile, rootMap, violations);

        Normalizer normalizer = new Normalizer(profile);
        DataNode.Obj root;
        try {
            root = normalizer.normalizeObject(rootMap, "");
        } catch (LimitExceededException e) {
            violations.put("(size)", RejectionReason.SIZE_LIMIT_EXCEEDED);
            return IngestionResult.reject(violations);
        } catch (CryptoException e) {
            violations.put("(crypto)", RejectionReason.PROCESSING_FAILURE);
            return IngestionResult.reject(violations);
        }
        violations.putAll(normalizer.violations);

        if (!violations.isEmpty()) {
            return IngestionResult.reject(violations);
        }
        // 节点数在构建完成后统一复核（数组截断后仍超限则在此拒绝）
        if (countNodes(root) > maxNodesPerRecord) {
            return IngestionResult.reject(Map.of("(size)", RejectionReason.SIZE_LIMIT_EXCEEDED));
        }
        return IngestionResult.ok(new NormalizedRecord(recordId, record.source(), root));
    }

    @SuppressWarnings("unchecked")
    private String resolveId(SourceProfile profile, String hint, Map<?, ?> root,
                             Map<String, RejectionReason> violations) {
        Object idVal = root.get(profile.idField());
        String id = idVal == null ? hint : scalarToString(idVal);
        if (id == null || id.isBlank()) {
            violations.put(profile.idField(), RejectionReason.MISSING_FIELD);
        }
        return id;
    }

    /**
     * 递归校验必填路径是否存在且非 null。数组沿路径透明下钻：
     * 例如 {@code contacts.name} 表示 contacts 数组任一元素含 name。
     */
    @SuppressWarnings("unchecked")
    private static void checkRequiredPresent(SourceProfile profile, Map<?, ?> root,
                                             Map<String, RejectionReason> violations) {
        for (FieldSpec spec : profile.fieldSpecs().values()) {
            if (!spec.required()) {
                continue;
            }
            if (!pathPresent(root, spec.path().split("\\."), 0)) {
                violations.putIfAbsent(spec.path(), RejectionReason.MISSING_FIELD);
            }
        }
    }

    private static boolean pathPresent(Object node, String[] segments, int index) {
        if (index >= segments.length) {
            return node != null;
        }
        if (node instanceof Map<?, ?> map) {
            if (!map.containsKey(segments[index])) {
                return false;
            }
            return pathPresent(map.get(segments[index]), segments, index + 1);
        }
        if (node instanceof List<?> list) {
            // 数组不带下标：任一元素含剩余路径即可；空数组视为缺失
            for (Object item : list) {
                if (pathPresent(item, segments, index)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    private static String parentPath(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "" : path.substring(0, dot);
    }

    private static int countNodes(DataNode node) {
        return switch (node) {
            case DataNode.Leaf ignored -> 1;
            case DataNode.Obj obj -> {
                int n = 1;
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    n += countNodes(e.getValue());
                }
                yield n;
            }
            case DataNode.Arr arr -> {
                int n = 1;
                for (DataNode item : arr.items()) {
                    n += countNodes(item);
                }
                yield n;
            }
        };
    }

    private static String scalarToString(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof Number || v instanceof Boolean) {
            return v.toString();
        }
        return null;
    }

    /** 递归归一器：边构建边校验，违例全部累积。 */
    private final class Normalizer {
        private final SourceProfile profile;
        private final Map<String, RejectionReason> violations = new LinkedHashMap<>();
        private int nodeBudget;

        private Normalizer(SourceProfile profile) {
            this.profile = profile;
            this.nodeBudget = maxNodesPerRecord;
        }

        private DataNode.Obj normalizeObject(Map<?, ?> map, String path) {
            List<Map.Entry<String, DataNode>> fields = new ArrayList<>(map.size());
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String key = String.valueOf(e.getKey());
                String childPath = path.isEmpty() ? key : path + "." + key;
                fields.add(new AbstractMap.SimpleImmutableEntry<>(key, normalizeValue(e.getValue(), childPath)));
            }
            return new DataNode.Obj(fields);
        }

        private DataNode normalizeValue(Object value, String path) {
            FieldSpec spec = profile.specFor(path);
            if (spec == null) {
                if (profile.rejectUnknownFields()) {
                    violations.putIfAbsent(path, RejectionReason.TYPE_MISMATCH);
                }
                return genericNode(value, path, profile.defaultClassification(), false);
            }
            if (value == null) {
                if (spec.required()) {
                    violations.putIfAbsent(path, RejectionReason.MISSING_FIELD);
                }
                return new DataNode.Leaf("", FieldMeta.plain(spec.classification()));
            }
            FieldKind actual = kindOf(value);
            if (spec.kind() != FieldKind.ANY && spec.kind() != actual) {
                violations.putIfAbsent(path, RejectionReason.TYPE_MISMATCH);
            }
            // 声明为标量却给了容器：按违规处理，容器仍递归保留但不加密
            boolean encrypt = spec.encryptAtRest() && actual == FieldKind.SCALAR;
            return genericNode(value, path, spec.classification(), encrypt);
        }

        private DataNode genericNode(Object value, String path, DataClassification classification,
                                     boolean encryptAtRest) {
            if (consumeBudget()) {
                throw new LimitExceededException("node budget exhausted at " + path);
            }
            if (value instanceof Map<?, ?> map) {
                return normalizeObject(map, path);
            }
            if (value instanceof List<?> list) {
                return normalizeArray(list, path, classification, encryptAtRest);
            }
            String s = scalarToString(value);
            if (s == null) {
                violations.putIfAbsent(path, RejectionReason.TYPE_MISMATCH);
                s = String.valueOf(value);
            }
            if (encryptAtRest && s != null && !s.isEmpty() && cryptoService != null) {
                // 落库加密失败属于处理失败：整条记录拒绝，不留下部分明文/密文混合状态
                s = cryptoService.encrypt(s);
                return new DataNode.Leaf(s, FieldMeta.encrypted(classification));
            }
            return new DataNode.Leaf(s, FieldMeta.plain(classification));
        }

        private DataNode.Arr normalizeArray(List<?> list, String path, DataClassification classification,
                                            boolean encryptAtRest) {
            boolean truncated = false;
            List<Object> items;
            if (list.size() > maxArrayLength) {
                if (truncateOversizeArrays) {
                    truncated = true;
                    items = new ArrayList<>(list.subList(0, maxArrayLength));
                } else {
                    violations.putIfAbsent(path, RejectionReason.SIZE_LIMIT_EXCEEDED);
                    items = new ArrayList<>(list);
                }
            } else {
                items = new ArrayList<>(list);
            }
            List<DataNode> built = new ArrayList<>(items.size());
            for (Object item : items) {
                // 数组透明：进入数组剥离数组字段名，元素内键名从父路径累计，
                // 与 Nodes.mapLeaves 的路径语义保持一致
                built.add(normalizeArrayElement(item, parentPath(path), classification, encryptAtRest));
            }
            return new DataNode.Arr(built, truncated);
        }

        private DataNode normalizeArrayElement(Object value, String path, DataClassification classification,
                                               boolean encryptAtRest) {
            if (value instanceof Map<?, ?> map) {
                return normalizeObject(map, path);
            }
            return genericNode(value, path, classification, encryptAtRest);
        }

        private boolean consumeBudget() {
            if (nodeBudget <= 0) {
                return true;
            }
            nodeBudget--;
            return false;
        }
    }

    private static FieldKind kindOf(Object value) {
        if (value instanceof Map<?, ?>) {
            return FieldKind.OBJECT;
        }
        if (value instanceof List<?>) {
            return FieldKind.ARRAY;
        }
        return FieldKind.SCALAR;
    }
}
