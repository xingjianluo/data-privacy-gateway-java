package com.github.xingjianluo.dataprivacygatewayjava.model;

/**
 * 叶子字段的元数据：数据分类与处理状态。
 *
 * @param classification 数据分类
 * @param encrypted      存储值是否为密文（{@code CipherToken} 字符串）
 * @param masked         存储值是否已脱敏
 */
public record FieldMeta(DataClassification classification, boolean encrypted, boolean masked) {

    public FieldMeta {
        if (classification == null) {
            throw new IllegalArgumentException("classification must not be null");
        }
        if (encrypted && masked) {
            throw new IllegalArgumentException("a field cannot be both encrypted and masked");
        }
    }

    public static FieldMeta plain(DataClassification classification) {
        return new FieldMeta(classification, false, false);
    }

    public static FieldMeta encrypted(DataClassification classification) {
        return new FieldMeta(classification, true, false);
    }

    public static FieldMeta masked(DataClassification classification) {
        return new FieldMeta(classification, false, true);
    }

    public FieldMeta asMasked() {
        return new FieldMeta(classification, false, true);
    }
}
