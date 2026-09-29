package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Set;

/**
 * 批量明文导出的限时授权（不可变快照）。
 * 绑定调用方、可访问记录范围、字段范围与有效期；过期/撤销后不可用。
 */
public final class ExportGrant {
    private final String grantId;
    private final String caller;
    private final Set<String> recordScope;
    private final Set<String> fieldScope;
    private final long issuedAt;
    private final long expiresAt;
    private final GrantStatus status;

    public ExportGrant(String grantId, String caller, Set<String> recordScope, Set<String> fieldScope,
                       long issuedAt, long expiresAt, GrantStatus status) {
        this.grantId = grantId;
        this.caller = caller;
        this.recordScope = recordScope;
        this.fieldScope = fieldScope;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = status;
    }

    public String grantId() { return grantId; }
    public String caller() { return caller; }
    public Set<String> recordScope() { return recordScope; }
    public Set<String> fieldScope() { return fieldScope; }
    public long issuedAt() { return issuedAt; }
    public long expiresAt() { return expiresAt; }
    public GrantStatus status() { return status; }

    public ExportGrant withStatus(GrantStatus newStatus) {
        return new ExportGrant(grantId, caller, recordScope, fieldScope, issuedAt, expiresAt, newStatus);
    }

    public String getGrantId() { return grantId; }
    public String getCaller() { return caller; }
    public Set<String> getRecordScope() { return recordScope; }
    public Set<String> getFieldScope() { return fieldScope; }
    public long getIssuedAt() { return issuedAt; }
    public long getExpiresAt() { return expiresAt; }
    public GrantStatus getStatus() { return status; }
}
