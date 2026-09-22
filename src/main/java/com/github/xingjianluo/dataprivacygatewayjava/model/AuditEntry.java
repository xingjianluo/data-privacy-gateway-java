package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Map;

/** 一条可复现的审计记录（不包含已解密原文）。 */
public final class AuditEntry {
    private final String eventId;
    private final long timestamp;
    private final String caller;
    private final String operation;
    private final String target;
    private final ReasonCode outcome;
    private final Long policyVersion;
    private final Integer keyVersion;
    private final String inputDigest;
    private final String rationale;
    private final Map<String, String> detail;

    public AuditEntry(String eventId, long timestamp, String caller, String operation, String target,
                      ReasonCode outcome, Long policyVersion, Integer keyVersion,
                      String inputDigest, String rationale, Map<String, String> detail) {
        this.eventId = eventId;
        this.timestamp = timestamp;
        this.caller = caller;
        this.operation = operation;
        this.target = target;
        this.outcome = outcome;
        this.policyVersion = policyVersion;
        this.keyVersion = keyVersion;
        this.inputDigest = inputDigest;
        this.rationale = rationale;
        this.detail = detail;
    }

    public String eventId() { return eventId; }
    public long timestamp() { return timestamp; }
    public String caller() { return caller; }
    public String operation() { return operation; }
    public String target() { return target; }
    public ReasonCode outcome() { return outcome; }
    public Long policyVersion() { return policyVersion; }
    public Integer keyVersion() { return keyVersion; }
    public String inputDigest() { return inputDigest; }
    public String rationale() { return rationale; }
    public Map<String, String> detail() { return detail; }

    // --- Jackson 友好访问器（与方法式访问器并存）---
    public String getEventId() { return eventId; }
    public long getTimestamp() { return timestamp; }
    public String getCaller() { return caller; }
    public String getOperation() { return operation; }
    public String getTarget() { return target; }
    public ReasonCode getOutcome() { return outcome; }
    public Long getPolicyVersion() { return policyVersion; }
    public Integer getKeyVersion() { return keyVersion; }
    public String getInputDigest() { return inputDigest; }
    public String getRationale() { return rationale; }
    public Map<String, String> getDetail() { return detail; }
}
