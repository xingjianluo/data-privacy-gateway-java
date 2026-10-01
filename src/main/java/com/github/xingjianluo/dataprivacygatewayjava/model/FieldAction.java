package com.github.xingjianluo.dataprivacygatewayjava.model;

/** 字段级判定动作。 */
public enum FieldAction {
    ALLOW,
    MASK,
    DENY,
    /** 点名的逻辑字段在该记录任何层级/包装/别名下都不存在或取不到。 */
    NOT_FOUND
}
