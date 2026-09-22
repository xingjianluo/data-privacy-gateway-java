package com.github.xingjianluo.dataprivacygatewayjava.ingest;

/**
 * 来源系统原始记录（JSON 风格载荷：Map / List / String / Number / Boolean / null）。
 */
public record SourceRecord(String source, String recordIdHint, Object payload) {
}
