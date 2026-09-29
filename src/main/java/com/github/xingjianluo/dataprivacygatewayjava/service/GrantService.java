package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.GrantStatus;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.ResolvedGrant;
import com.github.xingjianluo.dataprivacygatewayjava.store.GrantStore;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * 限时明文授权：发放、校验、撤销。
 * <p>授权与判定层口径统一：同一字段无论从单条入口还是批量导出入口，
 * 只要授权覆盖该调用方+记录+字段且在有效期内未撤销，结论都是放行；否则都不享受授权。</p>
 * <p>校验类结论（缺失/跨调用方/过期/撤销）全部写审计，便于追溯。</p>
 */
@Service
public class GrantService {

    private final GrantStore grantStore;
    private final GatewayProperties properties;
    private final AuditService auditService;

    public GrantService(GrantStore grantStore, GatewayProperties properties, AuditService auditService) {
        this.grantStore = grantStore;
        this.properties = properties;
        this.auditService = auditService;
    }

    /** 发放限时授权；空调用方/空范围拒绝；TTL 为正且受配置上限约束。 */
    public ExportGrant issue(String caller, Set<String> recordScope, Set<String> fieldScope, long ttlMillis) {
        if (caller == null || caller.isBlank()) {
            throw new GatewayException(ReasonCode.GRANT_INVALID, "授权必须绑定调用方");
        }
        if (recordScope == null || recordScope.isEmpty() || fieldScope == null || fieldScope.isEmpty()) {
            throw new GatewayException(ReasonCode.GRANT_INVALID, "授权必须明确记录范围与字段范围");
        }
        long cap = properties.getBatch().getMaxGrantTtlMillis();
        long ttl = Math.min(Math.max(ttlMillis, 1L), cap);
        long now = System.currentTimeMillis();
        ExportGrant grant = new ExportGrant(UUID.randomUUID().toString(), caller,
                Set.copyOf(recordScope), Set.copyOf(fieldScope), now, now + ttl, GrantStatus.ACTIVE);
        if (!grantStore.put(grant)) {
            // UUID 冲突实际不可达，保留受控失败
            throw new GatewayException(ReasonCode.GRANT_INVALID, "授权已存在");
        }
        auditService.record(caller, "GRANT_ISSUE", grant.grantId(), ReasonCode.ALLOWED,
                null, null, null,
                "发放限时明文授权，记录数=" + grant.recordScope().size()
                        + "，字段数=" + grant.fieldScope().size()
                        + "，有效期至=" + grant.expiresAt(),
                java.util.Map.of("ttlMillis", String.valueOf(ttl),
                        "records", sorted(grant.recordScope()),
                        "fields", sorted(grant.fieldScope())));
        return grant;
    }

    public ExportGrant get(String grantId) {
        return grantStore.get(grantId);
    }

    /** 撤销：仅绑定调用方可撤销自己的授权；撤销动作留痕。 */
    public boolean revoke(String caller, String grantId) {
        ExportGrant grant = grantStore.get(grantId);
        if (grant == null) {
            auditService.record(caller, "GRANT_REVOKE", String.valueOf(grantId),
                    ReasonCode.GRANT_NOT_FOUND, null, null, null, "撤销失败：授权不存在",
                    java.util.Map.of());
            throw new GatewayException(ReasonCode.GRANT_NOT_FOUND, "授权不存在：" + grantId);
        }
        if (!grant.caller().equals(caller)) {
            auditService.record(caller, "GRANT_REVOKE", grantId,
                    ReasonCode.GRANT_CALLER_MISMATCH, null, null, null,
                    "撤销失败：调用方与授权绑定方不一致（绑定=" + grant.caller() + "）",
                    java.util.Map.of("boundCaller", grant.caller()));
            throw new GatewayException(ReasonCode.GRANT_CALLER_MISMATCH,
                    "不能撤销他人的授权");
        }
        boolean changed = grantStore.revoke(grantId);
        auditService.record(caller, "GRANT_REVOKE", grantId, ReasonCode.ALLOWED,
                null, null, null,
                changed ? "授权已撤销，即时生效" : "授权此前已撤销", java.util.Map.of());
        return changed;
    }

    /**
     * 解析并严格校验授权（存在性 → 调用方绑定 → 有效期 → 状态）。
     * 任何不合格都写审计并抛出对应原因码。
     */
    public ResolvedGrant validate(String caller, String grantId) {
        return validate(caller, grantId, System.currentTimeMillis());
    }

    public ResolvedGrant validate(String caller, String grantId, long nowMillis) {
        String target = grantId == null ? "" : grantId;
        if (grantId == null || grantId.isBlank()) {
            auditService.record(caller, "GRANT_USE", target, ReasonCode.GRANT_NOT_FOUND,
                    null, null, null, "授权校验失败：未提供授权 id", java.util.Map.of());
            throw new GatewayException(ReasonCode.GRANT_NOT_FOUND, "未提供明文导出授权");
        }
        ExportGrant grant = grantStore.get(grantId);
        if (grant == null) {
            auditService.record(caller, "GRANT_USE", target, ReasonCode.GRANT_NOT_FOUND,
                    null, null, null, "授权校验失败：授权不存在", java.util.Map.of());
            throw new GatewayException(ReasonCode.GRANT_NOT_FOUND, "授权不存在：" + grantId);
        }
        if (!grant.caller().equals(caller)) {
            auditService.record(caller, "GRANT_USE", target, ReasonCode.GRANT_CALLER_MISMATCH,
                    null, null, null,
                    "授权校验失败：调用方与授权绑定方不一致（绑定=" + grant.caller() + "）",
                    java.util.Map.of("boundCaller", grant.caller()));
            throw new GatewayException(ReasonCode.GRANT_CALLER_MISMATCH,
                    "授权不属于该调用方，禁止使用");
        }
        if (nowMillis >= grant.expiresAt()) {
            auditService.record(caller, "GRANT_USE", target, ReasonCode.GRANT_EXPIRED,
                    null, null, null,
                    "授权校验失败：已于 " + grant.expiresAt() + " 过期", java.util.Map.of());
            throw new GatewayException(ReasonCode.GRANT_EXPIRED, "授权已过期");
        }
        if (grant.status() != GrantStatus.ACTIVE) {
            auditService.record(caller, "GRANT_USE", target, ReasonCode.GRANT_REVOKED,
                    null, null, null, "授权校验失败：授权已被撤销", java.util.Map.of());
            throw new GatewayException(ReasonCode.GRANT_REVOKED, "授权已被撤销");
        }
        return new ResolvedGrant(grant.grantId(), grant.caller(),
                new LinkedHashSet<>(grant.recordScope()), new LinkedHashSet<>(grant.fieldScope()));
    }

    /**
     * 批量交付前复核：快照存在、仍 ACTIVE、未过期。
     * 防止“开始时合法、处理期间被并发撤销/恰好过期”后仍交付明文。
     */
    public boolean stillValid(ResolvedGrant grant, long nowMillis) {
        if (grant == null) {
            return false;
        }
        ExportGrant fresh = grantStore.get(grant.grantId());
        return fresh != null
                && fresh.status() == GrantStatus.ACTIVE
                && nowMillis < fresh.expiresAt()
                && fresh.caller().equals(grant.caller());
    }

    public GrantStatus statusOf(String grantId) {
        ExportGrant g = grantStore.get(grantId);
        return g == null ? null : g.status();
    }

    private static String sorted(Set<String> values) {
        return new LinkedHashSet<>(values).toString();
    }
}
