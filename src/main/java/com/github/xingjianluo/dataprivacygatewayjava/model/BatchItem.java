package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/** 批量请求中的单条条目：目标记录 + 点名要访问的逻辑字段（空表示全部字段）。 */
public final class BatchItem {
    private final String recordId;
    private final List<String> fields;

    public BatchItem(String recordId, List<String> fields) {
        this.recordId = recordId;
        this.fields = fields == null ? List.of() : List.copyOf(fields);
    }

    public String recordId() { return recordId; }
    public List<String> fields() { return fields; }

    public String getRecordId() { return recordId; }
    public List<String> getFields() { return fields; }
}
