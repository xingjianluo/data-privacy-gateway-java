package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Map;

/** 接入结果：成功时带 recordId；拒绝时按字段给出可区分原因，绝不静默丢弃。 */
public final class IngestReport {
    private final boolean accepted;
    private final String recordId;
    private final String source;
    private final Map<String, ReasonCode> fieldRejections;
    private final ReasonCode reason;
    private final String message;

    public IngestReport(boolean accepted, String recordId, String source,
                        Map<String, ReasonCode> fieldRejections, ReasonCode reason, String message) {
        this.accepted = accepted;
        this.recordId = recordId;
        this.source = source;
        this.fieldRejections = fieldRejections;
        this.reason = reason;
        this.message = message;
    }

    public boolean accepted() { return accepted; }
    public String recordId() { return recordId; }
    public String source() { return source; }
    public Map<String, ReasonCode> fieldRejections() { return fieldRejections; }
    public ReasonCode reason() { return reason; }
    public String message() { return message; }

    // --- Jackson 友好访问器（与方法式访问器并存）---
    public boolean isAccepted() { return accepted; }
    public String getRecordId() { return recordId; }
    public String getSource() { return source; }
    public Map<String, ReasonCode> getFieldRejections() { return fieldRejections; }
    public ReasonCode getReason() { return reason; }
    public String getMessage() { return message; }
}
