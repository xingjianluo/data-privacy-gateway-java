package com.github.xingjianluo.dataprivacygatewayjava.ingest;

/**
 * 来源字段期望的结构类型，用于接入时的类型校验。
 */
public enum FieldKind {
    SCALAR, OBJECT, ARRAY, ANY
}
