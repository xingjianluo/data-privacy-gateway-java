package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.store.GrantStore;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

/**
 * 限时明文导出授权服务：签发 / 校验 / 撤销。
 * 校验失败一律抛带稳定原因码的领域异常并留审计（由调用方记录），
 * 授权只收紧不放宽：最终能否拿到明文仍取决于字段级判定。
 */
@Service
public class GrantService {

    private final GrantStore grantStore;
    private final GatewayProperties properties;

    public GrantService(GrantStore grantStore, GatewayProperties properties) {
        this.grantStore = grantStore;
        this.properties = properties;
    }

    /** 签发限时授权；ttl 非正数时用默认有效期，超出配置上限时按上限截断。 */
    public ExportGrant issue(String caller, Set<String> recordIds, Set<String> fields, long ttlMillis) {
        if (caller == null || caller.isBlank()) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "授权必须绑定具体调用方");
        }
        if (recordIds == null || recordIds.isEmpty()) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "授权必须绑定记录范围");
        }
        if (fields == null || fields.isEmpty()) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "授权必须绑定字段范围");
        }
        long ttl = ttlMillis > 0 ? ttlMillis : properties.getGrant().getDefaultTtlMillis();
        ttl = Math.min(ttl, properties.getGrant().getMaxTtlMillis());
        long now = System.currentTimeMillis();
        ExportGrant grant = new ExportGrant(UUID.randomUUID().toString(), caller,
                recordIds, fields, now, now + ttl);
        grantStore.put(grant);
        return grant;
    }

    /**
     * 校验授权存在、未过期、且属于该调用方；通过则返回授权快照。
     * 三种失败原因码彼此可区分：不存在/已撤销、已过期、跨调用方使用。
     */
    public ExportGrant requireValid(String grantId, String caller) {
        ExportGrant grant = grantStore.get(grantId);
        if (grant == null) {
            throw new GatewayException(ReasonCode.GRANT_NOT_FOUND,
                    "授权不存在或已撤销：" + grantId);
        }
        if (grant.expiredAt(System.currentTimeMillis())) {
            throw new GatewayException(ReasonCode.GRANT_EXPIRED,
                    "授权已过期：" + grantId + "（expiresAt=" + grant.expiresAt() + "）");
        }
        if (!grant.caller().equals(caller)) {
            throw new GatewayException(ReasonCode.GRANT_CALLER_MISMATCH,
                    "授权绑定调用方为 " + grant.caller() + "，当前调用方 " + caller + " 无权使用");
        }
        return grant;
    }

    public boolean revoke(String grantId) {
        return grantStore.revoke(grantId);
    }

    /** 定期清理已过期授权（过期授权即使未被清理也会在校验时失效）。 */
    @org.springframework.scheduling.annotation.Scheduled(
            fixedDelayString = "${privacy-gateway.retention.purge-interval-millis:60000}")
    public void scheduledPurge() {
        grantStore.purgeExpired(System.currentTimeMillis());
    }

    public ExportGrant get(String grantId) {
        return grantStore.get(grantId);
    }
}
