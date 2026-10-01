package com.github.xingjianluo.dataprivacygatewayjava.model;

/** 字段级判定动作。 */
public enum FieldAction {
    ALLOW,
    MASK,
    DENY,
    /** 点名的字段在记录中确实不存在（或在任何嵌套/数组/包装/别名位置都取不到）。 */
    NOT_FOUND
}
