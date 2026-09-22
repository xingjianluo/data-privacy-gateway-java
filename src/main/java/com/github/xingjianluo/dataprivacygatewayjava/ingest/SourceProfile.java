package com.github.xingjianluo.dataprivacygatewayjava.ingest;

import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;

import java.util.Map;

/**
 * 一个来源系统的字段画像：ID 字段、字段规格表、未知字段策略。
 */
public record SourceProfile(String source, String idField, Map<String, FieldSpec> fieldSpecs,
                            boolean rejectUnknownFields, DataClassification defaultClassification) {

    public SourceProfile {
        fieldSpecs = Map.copyOf(fieldSpecs);
        defaultClassification = defaultClassification == null ? DataClassification.INTERNAL : defaultClassification;
    }

    public FieldSpec specFor(String path) {
        return fieldSpecs.get(path);
    }
}
