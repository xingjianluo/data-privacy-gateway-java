package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/**
 * 批量请求中的单条：点名记录，可只点名要访问的逻辑字段（null/空表示全部字段）。
 */
public final class BatchItemRequest {
    private final String recordId;
    private final List<String> fields;

    public BatchItemRequest(String recordId, List<String> fields) {
        this.recordId = recordId;
        this.fields = fields;
    }

    public String recordId() { return recordId; }
    public List<String> fields() { return fields; }
}
