package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;
import java.util.Map;

/** 归一后的统一记录模型。data 为深拷贝后的纯 JSON 结构（Map/List/String/Number/Boolean/null）。 */
public final class NormalizedRecord {
    private final String recordId;
    private final String source;
    private final long ingestedAt;
    private final Map<String, Object> data;
    private final List<String> rejectedFields;

    public NormalizedRecord(String recordId, String source, long ingestedAt,
                            Map<String, Object> data, List<String> rejectedFields) {
        this.recordId = recordId;
        this.source = source;
        this.ingestedAt = ingestedAt;
        this.data = data;
        this.rejectedFields = rejectedFields;
    }

    public String recordId() { return recordId; }
    public String source() { return source; }
    public long ingestedAt() { return ingestedAt; }
    public Map<String, Object> data() { return data; }
    public List<String> rejectedFields() { return rejectedFields; }
}
