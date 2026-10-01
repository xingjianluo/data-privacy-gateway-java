package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.Policy;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 点名字段的深层定位与结构裁剪。
 * <p>点名的逻辑字段无论出现在记录的哪一层（子对象、数组元素）、以标量/密文信封直接出现，
 * 还是藏在 {@code {"value":x}} / {@code {"type":t,"value":x}} 包装、别名键下，
 * 都按与递归判定 {@code PrivacyGateway.process} 完全相同的「逻辑字段名」口径定位：
 * 本名、规则字段名或别名归一后命中。</p>
 * <ul>
 *   <li>普通对象按键判定：键名（或别名）命中点名名单时，该键的整个值作为「命中叶子」
 *       原样保留（值为数组/对象也整体保留，不再向下裁剪），并记录一条命中；</li>
 *   <li>数组裸标量 / 密文信封 / 包装元素继承「直接父键」逻辑名（与 process 一致），
 *       父键是点名字段才保留并记录命中；</li>
 *   <li>{@code {"value":x}} / {@code {"type":t,"value":x}} 包装以父键逻辑名判定，
 *       命中则整个包装保留，未命中则剥成 {@code {"value":…}} 单键桥继续向内部定位；</li>
 *   <li>未点名的键只作为通向内部命中的容器链保留，未点名内容绝不带出。</li>
 * </ul>
 * <p>裁剪与命中收集同一趟完成，命中路径与裁剪后视图严格对应（数组下标为压缩后下标）。
 * 返回全新结构，不修改入参。</p>
 */
@Service
public class FieldSelectionService {

    private final DecisionService decisionService;

    public FieldSelectionService(DecisionService decisionService) {
        this.decisionService = decisionService;
    }

    /** 一次命中：裁剪后视图中的路径 + 本地键名 + 规范逻辑名（别名→规则本名）。 */
    public record FieldHit(String path, String localName, String canonicalName) {
    }

    /** 裁剪结果：裁剪视图（永不为 null）+ 全部命中（按路径去重）。 */
    public record PrunedView(Map<String, Object> view, List<FieldHit> hits) {
    }

    /** 点名单归一为规范逻辑名（别名→规则本名），去重并保持点名顺序。 */
    public Set<String> canonicalNames(Policy policy, Collection<String> wanted) {
        Set<String> out = new LinkedHashSet<>();
        if (wanted == null) {
            return out;
        }
        for (String name : wanted) {
            if (name != null && !name.isBlank()) {
                out.add(canonical(policy, name));
            }
        }
        return out;
    }

    /**
     * 在完整记录上按点名字段裁剪：只保留命中分支及通向它的容器链。
     * 返回全新结构（入参不被修改）与命中清单（路径与返回视图严格对应）。
     */
    public PrunedView prune(Map<String, Object> data, Collection<String> wanted, Policy policy) {
        Set<String> canonicalWanted = canonicalNames(policy, wanted);
        Map<String, FieldHit> byPath = new LinkedHashMap<>();
        Object pruned = pruneNode(data, "$", null, canonicalWanted, policy, byPath);
        @SuppressWarnings("unchecked")
        Map<String, Object> view = pruned instanceof Map<?, ?> m
                ? (Map<String, Object>) m
                : new LinkedHashMap<String, Object>();
        return new PrunedView(view, List.copyOf(byPath.values()));
    }

    private String canonical(Policy policy, String name) {
        if (name == null) {
            return null;
        }
        FieldRule rule = decisionService.findRule(policy, name);
        return rule == null ? name : rule.field();
    }

    private void recordHit(Map<String, FieldHit> byPath,
                           String path, String localName, String canonicalName) {
        byPath.putIfAbsent(path, new FieldHit(path, localName, canonicalName));
    }

    // ------------------------------------------------------------------
    // 结构裁剪 + 命中收集（同一趟）：
    // 返回裁剪后的节点；返回 null 表示该分支无任何命中、整条丢弃
    // ------------------------------------------------------------------

    private Object pruneNode(Object node, String path, String wrapperField,
                             Set<String> wanted, Policy policy,
                             Map<String, FieldHit> byPath) {
        if (AesGcmCryptoService.isEnvelope(node)) {
            // 密文信封是标量叶子：按继承的父逻辑名判定
            if (wrapperField != null && wanted.contains(canonical(policy, wrapperField))) {
                recordHit(byPath, path, wrapperField, canonical(policy, wrapperField));
                return node;
            }
            return null;
        }
        if (node instanceof Map<?, ?> rawMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (isWrapperMap(map)) {
                return pruneWrapper(map, path, wrapperField, wanted, policy, byPath);
            }
            return pruneMap(map, path, wanted, policy, byPath);
        }
        if (node instanceof List<?> list) {
            return pruneList(list, path, wrapperField, wanted, policy, byPath);
        }
        // 裸标量叶子（含 null）：包装内部 value 或数组元素场景，按继承父逻辑名判定
        if (wrapperField != null && wanted.contains(canonical(policy, wrapperField))) {
            recordHit(byPath, path, wrapperField, canonical(policy, wrapperField));
            return node;
        }
        return null;
    }

    private Object pruneWrapper(Map<String, Object> wrapper, String path, String wrapperField,
                                Set<String> wanted, Policy policy,
                                Map<String, FieldHit> byPath) {
        String logical = wrapperField != null ? wrapperField : "value";
        String canon = canonical(policy, logical);
        if (wanted.contains(canon)) {
            // 包装的父逻辑字段被点名：整个包装（含 type 元数据与完整 value 子树）原样保留
            recordHit(byPath, path, logical, canon);
            return wrapper;
        }
        // 未点名的包装只作为通向内部命中的桥：剥成单键 {"value": 裁剪后的内部}
        Object innerPruned = pruneNode(wrapper.get("value"), path + ".value",
                "value", wanted, policy, byPath);
        if (innerPruned == null) {
            return null;
        }
        Map<String, Object> shell = new LinkedHashMap<>();
        shell.put("value", innerPruned);
        return shell;
    }

    private Object pruneMap(Map<String, Object> map, String path,
                            Set<String> wanted, Policy policy,
                            Map<String, FieldHit> byPath) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) {
            String key = e.getKey();
            Object child = e.getValue();
            String childPath = path + "." + key;
            String canon = canonical(policy, key);
            boolean keyWanted = wanted.contains(canon);
            if (keyWanted && isLeafValue(child)) {
                // 点名命中且值为标量 / 密文信封 / {"value":..} 包装叶子：
                // 整体保留并记录命中（包装在 process 中由父键逻辑名统一判定，是叶子承载）
                recordHit(byPath, childPath, key, canon);
                result.put(key, child);
            } else {
                Object sub = pruneNode(child, childPath, key, wanted, policy, byPath);
                if (sub != null) {
                    result.put(key, sub);
                }
            }
        }
        return result.isEmpty() ? null : result;
    }

    /**
     * 叶子承载：普通标量；密文信封虽是 Map 但语义是标量；
     * {@code {"value":x}} / {@code {"type","value"}} 包装在 process 中由父键逻辑名统一判定，
     * 也作为叶子整体处理。其余 Map/List 是需要逐元素继续判定的容器。
     */
    private boolean isLeafValue(Object value) {
        if (AesGcmCryptoService.isEnvelope(value)) {
            return true;
        }
        if (value instanceof Map<?, ?> map && isWrapperMap(map)) {
            return true;
        }
        return !(value instanceof Map<?, ?> || value instanceof List<?>);
    }

    private Object pruneList(List<?> list, String path, String wrapperField,
                             Set<String> wanted, Policy policy,
                             Map<String, FieldHit> byPath) {
        List<Object> result = new ArrayList<>();
        for (Object child : list) {
            String childPath = path + "[" + result.size() + "]";
            Object kept;
            if (AesGcmCryptoService.isEnvelope(child)) {
                kept = pruneNode(child, childPath, wrapperField, wanted, policy, byPath);
            } else if (child instanceof Map<?, ?> rawMap) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) rawMap;
                if (isWrapperMap(map)) {
                    kept = pruneWrapper(map, childPath, wrapperField, wanted, policy, byPath);
                } else {
                    // 普通对象元素：内部按键判定，不继承数组父键逻辑名（与 process 一致）
                    kept = pruneNode(map, childPath, null, wanted, policy, byPath);
                }
            } else {
                // 裸标量 / 嵌套数组：继承数组父键逻辑名
                kept = pruneNode(child, childPath, wrapperField, wanted, policy, byPath);
            }
            if (kept != null) {
                result.add(kept);
            }
        }
        return result.isEmpty() ? null : result;
    }

    private static boolean isWrapperMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            return false;
        }
        boolean single = map.size() == 1 && map.containsKey("value");
        boolean typed = map.size() == 2 && map.containsKey("value") && map.containsKey("type");
        return single || typed;
    }
}
