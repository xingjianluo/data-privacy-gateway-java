package com.github.xingjianluo.dataprivacygatewayjava.audit;

/**
 * 审计事件总体结论：允许 / 脱敏 / 拒绝 / 失败。
 */
public enum AuditOutcome {
    ALLOW, MASK, DENY, FAIL
}
