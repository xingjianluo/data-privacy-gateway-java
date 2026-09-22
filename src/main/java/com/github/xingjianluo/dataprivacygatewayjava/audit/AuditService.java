package com.github.xingjianluo.dataprivacygatewayjava.audit;

import com.github.xingjianluo.dataprivacygatewayjava.access.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.model.CallerIdentity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * 审计服务：为允许 / 脱敏 / 拒绝 / 失败生成可复现的判定依据。
 * <p>审计内容只包含输入摘要（SHA-256 哈希前缀）与字段级依据（路径、结论、原因、版本），
 * 不写入任何原始值或解密中间值。审计写入结果只记录成功与否，绝不向主流程抛异常。
 */
public class AuditService {

    private final AuditStore store;
    private final long retentionDays;
    private volatile Clock clock = Clock.systemUTC();

    public AuditService(AuditStore store, long retentionDays) {
        this.store = store;
        this.retentionDays = retentionDays;
    }

    public void setClock(Clock clock) {
        this.clock = clock;
    }

    public AuditEvent recordAccess(CallerIdentity caller, String recordId, AuditOutcome outcome,
                                   String reason, String inputSummary, List<FieldDecision> basis,
                                   long policyVersion, int keyRingVersion) {
        Instant now = clock.instant();
        List<String> fieldBasis = basis.stream()
                .map(d -> d.path() + "=" + d.outcome()
                        + "(policy-v" + d.policyVersion() + ",key-v" + d.keyVersion() + ")"
                        + (d.reason() == null || d.reason().isBlank() ? "" : ":" + d.reason()))
                .toList();
        Instant expiresAt = now.plusSeconds(retentionDays * 24 * 60 * 60);
        AuditEvent event = new AuditEvent(
                UUID.randomUUID().toString(), now,
                caller == null ? "anonymous" : caller.callerId(),
                recordId, outcome, reason, inputSummary, fieldBasis,
                policyVersion, keyRingVersion, expiresAt);
        store.record(event); // 失败只计数，主流程结论不变
        return event;
    }

    /**
     * 计算输入摘要：对 调用方ID / 记录ID / 有序字段路径列表 做稳定 SHA-256，
     * 同样的输入永远得到同样的摘要，从而可复现且不含可识别原文。
     */
    public String summarize(String callerId, String recordId, List<String> fieldPaths) {
        String canonical = String.valueOf(callerId) + "|" + String.valueOf(recordId) + "|"
                + String.join(",", fieldPaths.stream().sorted().toList());
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest, 0, 12);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 为 JDK 必备；极端情况下退化为确定性弱摘要，不阻断审计
            return "len:" + canonical.length() + ":" + Integer.toHexString(canonical.hashCode());
        }
    }
}
