package com.github.xingjianluo.dataprivacygatewayjava.ingest;

import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;

/**
 * 来源字段规格。
 *
 * @param path           字段路径（点分路径，数组无需下标）
 * @param classification 归一化后的数据分类
 * @param required       是否必填
 * @param kind           期望结构类型
 */
public record FieldSpec(String path, DataClassification classification, boolean required,
                        FieldKind kind, boolean encryptAtRest) {

    public FieldSpec(String path, DataClassification classification, boolean required, FieldKind kind) {
        this(path, classification, required, kind, false);
    }

    public FieldSpec {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("field path must not be blank");
        }
        if (classification == null) {
            throw new IllegalArgumentException("classification must not be null");
        }
        kind = kind == null ? FieldKind.ANY : kind;
    }
}
