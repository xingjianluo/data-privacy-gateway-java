package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Set;

/**
 * 校验通过后供判定层使用的授权视图（只含范围，不含任何密钥/明文）。
 * 判定口径：调用方持证等级不足时，若授权覆盖该记录+字段则仍可放行原文。
 */
public final class ResolvedGrant {
    private final String grantId;
    private final String caller;
    private final Set<String> recordScope;
    private final Set<String> fieldScope;

    public ResolvedGrant(String grantId, String caller, Set<String> recordScope, Set<String> fieldScope) {
        this.grantId = grantId;
        this.caller = caller;
        this.recordScope = recordScope;
        this.fieldScope = fieldScope;
    }

    public String grantId() { return grantId; }
    public String caller() { return caller; }
    public Set<String> recordScope() { return recordScope; }
    public Set<String> fieldScope() { return fieldScope; }

    /** 授权是否覆盖指定记录上的指定逻辑字段。 */
    public boolean covers(String recordId, String field) {
        return recordScope.contains(recordId) && fieldScope.contains(field);
    }
}
