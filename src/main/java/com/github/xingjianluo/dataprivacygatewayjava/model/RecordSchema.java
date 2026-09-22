package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/** 多来源记录接入时的归一化契约。 */
public final class RecordSchema {
    private final String name;
    private final List<FieldSpec> fields;

    public RecordSchema(String name, List<FieldSpec> fields) {
        this.name = name;
        this.fields = fields;
    }

    public String name() { return name; }
    public List<FieldSpec> fields() { return fields; }
}
