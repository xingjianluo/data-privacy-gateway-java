package com.github.xingjianluo.dataprivacygatewayjava.model;

/**
 * 接入拒绝原因，必须可区分，禁止静默丢弃。
 */
public enum RejectionReason {
    MISSING_FIELD("缺失必填字段"),
    TYPE_MISMATCH("字段类型不匹配"),
    UNKNOWN_CLASSIFICATION("未知数据分类"),
    SIZE_LIMIT_EXCEEDED("超出允许规模"),
    MALFORMED_RECORD("记录格式无法解析"),
    PROCESSING_FAILURE("归一处理失败");

    private final String description;

    RejectionReason(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
