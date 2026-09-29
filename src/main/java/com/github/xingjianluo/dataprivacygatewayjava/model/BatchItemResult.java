package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 批量结果中的单条结论：允许/脱敏/拒绝在同一条内分清楚，
 * 单条失败不拖垮整批（ok=false 时 view 为 null，reason 给出可区分原因）。
 */
public final class BatchItemResult {
    private final String recordId;
    private final boolean ok;
    private final ReasonCode reason;
    private final Map<String, Object> view;
    private final List<FieldDecision> decisions;
    private final String auditEventId;
    private final boolean truncated;
    private final long policyVersion;
    private final Integer keyVersion;

    public BatchItemResult(String recordId, boolean ok, ReasonCode reason, Map<String, Object> view,
                           List<FieldDecision> decisions, String auditEventId, boolean truncated,
                           long policyVersion, Integer keyVersion) {
        this.recordId = recordId;
        this.ok = ok;
        this.reason = reason;
        this.view = view;
        this.decisions = decisions;
        this.auditEventId = auditEventId;
        this.truncated = truncated;
        this.policyVersion = policyVersion;
        this.keyVersion = keyVersion;
    }

    public String recordId() { return recordId; }
    public boolean ok() { return ok; }
    public ReasonCode reason() { return reason; }
    public Map<String, Object> view() { return view; }
    public List<FieldDecision> decisions() { return decisions; }
    public String auditEventId() { return auditEventId; }
    public boolean truncated() { return truncated; }
    public long policyVersion() { return policyVersion; }
    public Integer keyVersion() { return keyVersion; }

    // --- Jackson 友好访问器 ---
    public String getRecordId() { return recordId; }
    public boolean isOk() { return ok; }
    public ReasonCode getReason() { return reason; }
    public Map<String, Object> getView() { return view; }
    public List<FieldDecision> getDecisions() { return decisions; }
    public String getAuditEventId() { return auditEventId; }
    public boolean isTruncated() { return truncated; }
    public long getPolicyVersion() { return policyVersion; }
    public Integer getKeyVersion() { return keyVersion; }
}
