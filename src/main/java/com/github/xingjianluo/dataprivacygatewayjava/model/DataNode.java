package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

/**
 * 归一化后的统一数据节点：对象 / 数组 / 叶子。
 * <p>叶子值仅允许 {@code String}（标量统一序列化为字符串），密文以
 * {@code CipherToken} 的字符串形式存放在叶子中，由 {@link FieldMeta#encrypted()} 标识。
 */
public sealed interface DataNode permits DataNode.Leaf, DataNode.Obj, DataNode.Arr {

    /** 叶子节点。 */
    record Leaf(String value, FieldMeta meta) implements DataNode {
        public Leaf {
            if (meta == null) {
                throw new IllegalArgumentException("leaf meta must not be null");
            }
        }
    }

    /** 对象节点：保持插入顺序，允许重复键名（重复字段不得漏处理）。 */
    final class Obj implements DataNode {
        private final List<Map.Entry<String, DataNode>> fields;

        public Obj(List<Map.Entry<String, DataNode>> fields) {
            this.fields = List.copyOf(fields);
        }

        /** 便利构造：逐个给出键与节点，允许重复键名。 */
        public static Obj of(Object... keyNodePairs) {
            if (keyNodePairs.length % 2 != 0) {
                throw new IllegalArgumentException("key/node pairs must be even");
            }
            List<Map.Entry<String, DataNode>> list = new java.util.ArrayList<>(keyNodePairs.length / 2);
            for (int i = 0; i < keyNodePairs.length; i += 2) {
                list.add(new AbstractMap.SimpleImmutableEntry<>(
                        (String) keyNodePairs[i], (DataNode) keyNodePairs[i + 1]));
            }
            return new Obj(list);
        }

        public List<Map.Entry<String, DataNode>> fields() {
            return fields;
        }
    }

    /** 数组节点。 */
    final class Arr implements DataNode {
        private final List<DataNode> items;
        private final boolean truncated;

        public Arr(List<DataNode> items) {
            this(items, false);
        }

        public Arr(List<DataNode> items, boolean truncated) {
            this.items = List.copyOf(items);
            this.truncated = truncated;
        }

        public List<DataNode> items() {
            return items;
        }

        /** 是否因规模上限被截断。 */
        public boolean truncated() {
            return truncated;
        }
    }
}
