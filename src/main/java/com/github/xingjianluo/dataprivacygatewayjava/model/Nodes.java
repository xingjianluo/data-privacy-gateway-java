package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 数据树遍历 / 重建工具。
 * <p>路径规则：对象用键名以 "." 连接；数组元素不追加下标——因此同一字段无论嵌套多深、
 * 无论是否被数组或重复键包装，都具有相同路径，从而得到一致的判定与脱敏结果。
 * 重建时保持对象字段顺序（含重复键）与数组截断标记，保证不漏处理任何叶子。
 */
public final class Nodes {

    private Nodes() {
    }

    /** 统计全部叶子数量（含数组内、重复键下）。 */
    public static int countLeaves(DataNode node) {
        return switch (node) {
            case DataNode.Leaf ignored -> 1;
            case DataNode.Obj obj -> {
                int n = 0;
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    n += countLeaves(e.getValue());
                }
                yield n;
            }
            case DataNode.Arr arr -> {
                int n = 0;
                for (DataNode item : arr.items()) {
                    n += countLeaves(item);
                }
                yield n;
            }
        };
    }

    /** 对每个叶子做变换并不可变地重建整棵树；叶子路径不含数组下标。 */
    public static DataNode mapLeaves(DataNode node, LeafTransform transform) {
        return rebuild(node, "", transform);
    }

    private static DataNode rebuild(DataNode node, String path, LeafTransform transform) {
        return switch (node) {
            case DataNode.Leaf leaf -> transform.apply(path, leaf);
            case DataNode.Obj obj -> {
                List<Map.Entry<String, DataNode>> rebuilt = new ArrayList<>(obj.fields().size());
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    String childPath = path.isEmpty() ? e.getKey() : path + "." + e.getKey();
                    rebuilt.add(new AbstractMap.SimpleImmutableEntry<>(
                            e.getKey(), rebuild(e.getValue(), childPath, transform)));
                }
                yield new DataNode.Obj(rebuilt);
            }
            case DataNode.Arr arr -> {
                // 数组透明：进入数组时剥离数组字段名这一段路径，使得
                // aliases=[{name=...}] 内部 name 的路径仍是 "name"，
                // 与根层 name、对象内 {name:...}（后者路径为对象键+.name 除外）保持
                // "同名字段同结论"。具体规则：路径最后一段若为数组字段则视为包装层。
                String elementPath = parentPath(path);
                List<DataNode> rebuilt = new ArrayList<>(arr.items().size());
                for (DataNode item : arr.items()) {
                    rebuilt.add(rebuild(item, elementPath, transform));
                }
                yield new DataNode.Arr(rebuilt, arr.truncated());
            }
        };
    }

    /** 去掉路径最后一段（数组字段名），使数组元素从父路径继续累计键名。 */
    private static String parentPath(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "" : path.substring(0, dot);
    }

    /** 转换为 JSON 友好的 Map/List/String 视图（叶子输出值，重复键保留为同名键的数组语义由列表承载）。 */
    public static Object toJsonView(DataNode node) {
        return switch (node) {
            case DataNode.Leaf leaf -> leaf.value();
            case DataNode.Obj obj -> {
                // 保留重复键：同名键聚合成 JSON 数组
                java.util.LinkedHashMap<String, Object> view = new java.util.LinkedHashMap<>();
                java.util.LinkedHashMap<String, Integer> counts = new java.util.LinkedHashMap<>();
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    counts.merge(e.getKey(), 1, Integer::sum);
                }
                java.util.Set<String> repeated = new java.util.HashSet<>();
                counts.forEach((k, c) -> {
                    if (c > 1) {
                        repeated.add(k);
                        view.put(k, new ArrayList<>());
                    }
                });
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    Object child = toJsonView(e.getValue());
                    if (repeated.contains(e.getKey())) {
                        @SuppressWarnings("unchecked")
                        List<Object> arr = (List<Object>) view.get(e.getKey());
                        arr.add(child);
                    } else {
                        view.put(e.getKey(), child);
                    }
                }
                yield view;
            }
            case DataNode.Arr arr -> {
                List<Object> items = new ArrayList<>(arr.items().size());
                for (DataNode item : arr.items()) {
                    items.add(toJsonView(item));
                }
                if (arr.truncated()) {
                    // 截断事实必须随数据可见，不能静默
                    List<Object> wrapped = new ArrayList<>(items.size() + 1);
                    wrapped.addAll(items);
                    wrapped.add("[TRUNCATED]");
                    yield wrapped;
                }
                yield items;
            }
        };
    }

    /** 叶子变换：入参为叶子路径（不含数组下标）与叶子，返回新叶子。 */
    @FunctionalInterface
    public interface LeafTransform {
        DataNode.Leaf apply(String path, DataNode.Leaf leaf);
    }
}
