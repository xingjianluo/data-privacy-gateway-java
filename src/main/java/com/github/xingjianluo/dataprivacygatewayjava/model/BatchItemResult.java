package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 批量结果中的单条结论：允许 / 脱敏 / 拒绝 / 失败混在同一批里也能逐条区分。
 * view 仅在成功（ALLOWED / MASKED / TRUNCATED）时非空；拒绝与失败不携带任何字段视图。
 */
public final class BatchItemResult {
    private final String recordId;
    private final ReasonCode outcome;
    private final Map<String, Object> view;
    private final List<FieldDecision> decisions;
    private final long policyVersion;
    private final Integer keyVersion;
    private final String auditEventId;
    private final boolean truncated;
    private final String message;

    public BatchItemResult(String recordId, ReasonCode outcome, Map<String, Object> view,
                           List<FieldDecision> decisions, long policyVersion, Integer keyVersion,
                           String auditEventId, boolean truncated, String message) {
        this.recordId = recordId;
        this.outcome = outcome;
        this.view = view;
        this.decisions = decisions == null ? List.of() : List.copyOf(decisions);
        this.policyVersion = policyVersion;
        this.keyVersion = keyVersion;
        this.auditEventId = auditEventId;
        this.truncated = truncated;
        this.message = message;
    }

    public boolean ok() {
        return outcome == ReasonCode.ALLOWED
                || outcome == ReasonCode.MASKED_INSUFFICIENT_CLEARANCE
                || outcome == ReasonCode.TRUNCATED_BY_LIMIT;
    }

    public String recordId() { return recordId; }
    public ReasonCode outcome() { return outcome; }
    public Map<String, Object> view() { return view; }
    public List<FieldDecision> decisions() { return decisions; }
    public long policyVersion() { return policyVersion; }
    public Integer keyVersion() { return keyVersion; }
    public String auditEventId() { return auditEventId; }
    public boolean truncated() { return truncated; }
    public String message() { return message; }

    public String getRecordId() { return recordId; }
    public ReasonCode getOutcome() { return outcome; }
    public Map<String, Object> getView() { return view; }
    public List<FieldDecision> getDecisions() { return decisions; }
    public long getPolicyVersion() { return policyVersion; }
    public Integer getKeyVersion() { return keyVersion; }
    public String getAuditEventId() { return auditEventId; }
    public boolean isTruncated() { return truncated; }
    public String getMessage() { return message; }
}
