package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Set;

/**
 * 限时明文导出授权（不可变）。绑定具体调用方、记录范围、字段范围与明确有效期；
 * 撤销 = 从授权库移除，过期 = expiresAt 到达后自动失效。
 */
public final class ExportGrant {
    private final String grantId;
    private final String caller;
    private final Set<String> recordIds;
    private final Set<String> fields;
    private final long issuedAt;
    private final long expiresAt;

    public ExportGrant(String grantId, String caller, Set<String> recordIds, Set<String> fields,
                       long issuedAt, long expiresAt) {
        this.grantId = grantId;
        this.caller = caller;
        this.recordIds = recordIds == null ? Set.of() : Set.copyOf(recordIds);
        this.fields = fields == null ? Set.of() : Set.copyOf(fields);
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String grantId() { return grantId; }
    public String caller() { return caller; }
    public Set<String> recordIds() { return recordIds; }
    public Set<String> fields() { return fields; }
    public long issuedAt() { return issuedAt; }
    public long expiresAt() { return expiresAt; }

    public boolean expiredAt(long nowMillis) { return nowMillis >= expiresAt; }

    public String getGrantId() { return grantId; }
    public String getCaller() { return caller; }
    public Set<String> getRecordIds() { return recordIds; }
    public Set<String> getFields() { return fields; }
    public long getIssuedAt() { return issuedAt; }
    public long getExpiresAt() { return expiresAt; }
}
