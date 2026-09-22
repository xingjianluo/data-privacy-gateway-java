package com.github.xingjianluo.dataprivacygatewayjava.model;

/**
 * 敏感数据分类（敏感度从低到高）。
 */
public enum DataClassification {
    PUBLIC(0),
    INTERNAL(1),
    PII(2),
    FINANCIAL(3),
    SECRET(4);

    private final int level;

    DataClassification(int level) {
        this.level = level;
    }

    public int level() {
        return level;
    }

    /**
     * 按名称解析分类，无法识别时返回 null（由上层给出可区分的拒绝原因，不静默丢弃）。
     */
    public static DataClassification fromName(String name) {
        if (name == null) {
            return null;
        }
        for (DataClassification c : values()) {
            if (c.name().equalsIgnoreCase(name)) {
                return c;
            }
        }
        return null;
    }
}
