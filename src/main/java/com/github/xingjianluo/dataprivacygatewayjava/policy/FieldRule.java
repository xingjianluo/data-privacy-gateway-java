package com.github.xingjianluo.dataprivacygatewayjava.policy;

import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;

/**
 * 字段级访问规则（按字段路径配置；缺省规则按数据分类匹配）。
 *
 * @param fieldPath      字段路径（数组元素不写下标），"*" 表示缺省规则
 * @param minClearance   读取原始值所需的最低许可分类
 * @param encryptAtRest  落库是否必须加密
 */
public record FieldRule(String fieldPath, DataClassification minClearance, boolean encryptAtRest) {

    public FieldRule {
        if (fieldPath == null || fieldPath.isBlank()) {
            throw new IllegalArgumentException("fieldPath must not be blank");
        }
        if (minClearance == null) {
            throw new IllegalArgumentException("minClearance must not be null");
        }
    }

    /** 缺省规则：按字段自身分类作为最低许可。 */
    public static FieldRule defaultRule() {
        return new FieldRule("*", DataClassification.INTERNAL, false);
    }
}
