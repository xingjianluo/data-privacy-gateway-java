package com.github.xingjianluo.dataprivacygatewayjava.audit;

import java.time.Instant;
import java.util.List;

/**
 * 一条审计记录：只保存输入摘要（哈希/路径），不保存原始值，保证可复现判定依据。
 */
public record AuditEvent(String eventId, Instant timestamp, String callerId, String recordId,
                         AuditOutcome outcome, String reason,
                         String inputSummary, List<String> fieldBasis,
                         long policyVersion, int keyRingVersion, Instant expiresAt) {
}
