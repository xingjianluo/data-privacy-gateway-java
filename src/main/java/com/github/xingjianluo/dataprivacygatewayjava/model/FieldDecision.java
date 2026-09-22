package com.github.xingjianluo.dataprivacygatewayjava.model;

/**
 * 单个字段的可解释判定依据。
 * path 为规范化字段路径（如 user.contacts[1].phone）。
 */
public final class FieldDecision {
    private final String path;
    private final String field;
    private final FieldAction action;
    private final ReasonCode reason;
    private final Level callerLevel;
    private final Level requiredLevel;
    private final long policyVersion;

    public FieldDecision(String path, String field, FieldAction action, ReasonCode reason,
                         Level callerLevel, Level requiredLevel, long policyVersion) {
        this.path = path;
        this.field = field;
        this.action = action;
        this.reason = reason;
        this.callerLevel = callerLevel;
        this.requiredLevel = requiredLevel;
        this.policyVersion = policyVersion;
    }

    public String path() { return path; }
    public String field() { return field; }
    public FieldAction action() { return action; }
    public ReasonCode reason() { return reason; }
    public Level callerLevel() { return callerLevel; }
    public Level requiredLevel() { return requiredLevel; }
    public long policyVersion() { return policyVersion; }

    public String rationale() {
        return "path=" + path + " field=" + field + " action=" + action
                + " reason=" + reason + " caller=" + callerLevel
                + " required=" + requiredLevel + " policyVersion=" + policyVersion;
    }

    // --- Jackson 友好访问器（与方法式访问器并存）---
    public String getPath() { return path; }
    public String getField() { return field; }
    public FieldAction getAction() { return action; }
    public ReasonCode getReason() { return reason; }
    public Level getCallerLevel() { return callerLevel; }
    public Level getRequiredLevel() { return requiredLevel; }
    public long getPolicyVersion() { return policyVersion; }
}
