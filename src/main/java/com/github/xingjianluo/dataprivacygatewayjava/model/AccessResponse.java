package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;
import java.util.Map;

/** 访问结果：视图数据 + 版本戳 + 每字段判定依据。 */
public final class AccessResponse {
    private final String recordId;
    private final Map<String, Object> view;
    private final long policyVersion;
    private final Integer currentKeyVersion;
    private final List<FieldDecision> decisions;
    private final ReasonCode overallReason;
    private final String auditEventId;
    private final boolean truncated;

    public AccessResponse(String recordId, Map<String, Object> view, long policyVersion,
                          Integer currentKeyVersion, List<FieldDecision> decisions,
                          ReasonCode overallReason, String auditEventId, boolean truncated) {
        this.recordId = recordId;
        this.view = view;
        this.policyVersion = policyVersion;
        this.currentKeyVersion = currentKeyVersion;
        this.decisions = decisions;
        this.overallReason = overallReason;
        this.auditEventId = auditEventId;
        this.truncated = truncated;
    }

    public String recordId() { return recordId; }
    public Map<String, Object> view() { return view; }
    public long policyVersion() { return policyVersion; }
    public Integer currentKeyVersion() { return currentKeyVersion; }
    public List<FieldDecision> decisions() { return decisions; }
    public ReasonCode overallReason() { return overallReason; }
    public String auditEventId() { return auditEventId; }
    public boolean truncated() { return truncated; }

    // --- Jackson 友好访问器（与方法式访问器并存）---
    public String getRecordId() { return recordId; }
    public Map<String, Object> getView() { return view; }
    public long getPolicyVersion() { return policyVersion; }
    public Integer getCurrentKeyVersion() { return currentKeyVersion; }
    public List<FieldDecision> getDecisions() { return decisions; }
    public ReasonCode getOverallReason() { return overallReason; }
    public String getAuditEventId() { return auditEventId; }
    public boolean isTruncated() { return truncated; }
}
