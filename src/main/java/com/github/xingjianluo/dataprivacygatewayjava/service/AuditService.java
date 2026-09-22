package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AuditEntry;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.store.AuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 审计服务。
 * 允许 / 脱敏 / 拒绝 / 失败全部留痕，记录输入摘要（不留原文）、策略版本、密钥版本与逐条判定依据；
 * 审计写入失败仅标记 AUDIT_WRITE_FAILED，绝不改变主流程结论；
 * 定时按 TTL 整条清除过期数据。
 */
@Service
public class AuditService {

    private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);

    private final AuditStore store;
    private final GatewayProperties properties;

    public AuditService(AuditStore store, GatewayProperties properties) {
        this.store = store;
        this.properties = properties;
    }

    /** 记录一条审计，永不向调用方抛异常；始终返回事件 id，便于主流程追溯。 */
    public String record(String caller, String operation, String target, ReasonCode outcome,
                         Long policyVersion, Integer keyVersion, String inputDigest,
                         String rationale, Map<String, String> detail) {
        String eventId = UUID.randomUUID().toString();
        AuditEntry entry = new AuditEntry(eventId, System.currentTimeMillis(), caller, operation, target,
                outcome, policyVersion, keyVersion, inputDigest, rationale,
                detail == null ? Map.of() : new LinkedHashMap<>(detail));
        boolean ok = false;
        try {
            ok = store.append(entry);
        } catch (RuntimeException e) {
            // 审计存储自身故障：只记本地日志，不影响主流程
            LOG.warn("审计写入失败 eventId={} target={} outcome={}", eventId, target, outcome, e);
        }
        if (!ok) {
            LOG.warn("审计写入被拒绝(失败注入/容量) eventId={} target={} outcome={} reason={}",
                    eventId, target, outcome, ReasonCode.AUDIT_WRITE_FAILED);
        }
        return eventId;
    }

    public List<AuditEntry> query(String recordId) {
        return store.query(recordId);
    }

    public int purgeNow() {
        return store.purgeExpired(System.currentTimeMillis() - properties.getRetention().getAuditTtlMillis());
    }

    /** 汇总字段级判定为一条访问审计。 */
    public void recordAccess(AccessRequest request, long policyVersion, Integer keyVersion,
                             String inputDigest, ReasonCode outcome, List<FieldDecision> decisions,
                             boolean auditWriteFailed) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("rawRequested", String.valueOf(request.rawRequested()));
        detail.put("auditWriteFailed", String.valueOf(auditWriteFailed));
        int allow = 0, mask = 0, deny = 0;
        StringBuilder rationale = new StringBuilder("整体结论=").append(outcome)
                .append("；字段判定：");
        for (FieldDecision d : decisions) {
            switch (d.action()) {
                case ALLOW -> allow++;
                case MASK -> mask++;
                case DENY -> deny++;
            }
            rationale.append('[').append(d.rationale()).append("] ");
        }
        detail.put("counts", "ALLOW=" + allow + ",MASK=" + mask + ",DENY=" + deny);
        record(request.caller(), "ACCESS", request.recordId(), outcome,
                policyVersion, keyVersion, inputDigest, rationale.toString().trim(), detail);
    }

    /** 默认每分钟清理一次过期审计数据。 */
    @Scheduled(fixedDelayString = "${privacy-gateway.retention.purge-interval-millis:60000}")
    public void scheduledPurge() {
        int removed = purgeNow();
        if (removed > 0) {
            LOG.info("审计留存清理：移除过期条目 {} 条", removed);
        }
    }
}
