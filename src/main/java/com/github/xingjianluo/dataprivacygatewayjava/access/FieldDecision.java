package com.github.xingjianluo.dataprivacygatewayjava.access;

/**
 * 单字段判定依据（审计可追溯）：结论、路径、策略/密钥版本、原因说明。
 */
public record FieldDecision(String path, DecisionOutcome outcome, String reason,
                            long policyVersion, int keyVersion) {
}
