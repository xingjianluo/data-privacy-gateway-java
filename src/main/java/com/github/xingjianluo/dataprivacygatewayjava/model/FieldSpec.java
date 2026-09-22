package com.github.xingjianluo.dataprivacygatewayjava.model;

/** 接入时对顶层字段的声明：名称、期望类型、是否必填。 */
public final class FieldSpec {
    private final String name;
    private final JsonType type;
    private final boolean required;

    public FieldSpec(String name, JsonType type, boolean required) {
        this.name = name;
        this.type = type;
        this.required = required;
    }

    public String name() { return name; }
    public JsonType type() { return type; }
    public boolean required() { return required; }
}
