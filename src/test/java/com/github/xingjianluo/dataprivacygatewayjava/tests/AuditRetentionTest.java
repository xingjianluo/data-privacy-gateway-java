package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AuditEntry;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.AuditStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AuditRetentionTest {

    private static final Logger LOG = LoggerFactory.getLogger(AuditRetentionTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired AuditStore auditStore;
    @Autowired GatewayProperties properties;

    @AfterEach
    void reset() {
        auditStore.injectFailure(false);
        auditStore.clear();
    }

    @Test
    void allow_mask_deny_and_failure_all_leave_reproducible_trace() {
        gateway.ingest("crm", "ar-1", Map.of("phone", "13800001111", "idCard", "X"), null);
        gateway.access(new AccessRequest("boss", Level.RESTRICTED, "ar-1", false));
        gateway.access(new AccessRequest("guest", Level.PUBLIC, "ar-1", false));
        assertThrows(GatewayException.class,
                () -> gateway.access(new AccessRequest("guest", Level.PUBLIC, "ar-1", true)));
        List<AuditEntry> entries = auditStore.query("ar-1");
        LOG.info("[AUDIT] 条目数={}", entries.size());
        for (AuditEntry e : entries) {
            LOG.info("[AUDIT] event={} caller={} outcome={} policyV={} keyV={} digest={} rationale={}",
                    e.eventId(), e.caller(), e.outcome(), e.policyVersion(), e.keyVersion(),
                    e.inputDigest(), e.rationale());
        }
        assertTrue(entries.stream().anyMatch(e -> e.outcome() == ReasonCode.ALLOWED));
        assertTrue(entries.stream().anyMatch(e -> e.outcome() == ReasonCode.MASKED_INSUFFICIENT_CLEARANCE));
        assertTrue(entries.stream().anyMatch(e -> e.outcome() == ReasonCode.DENIED_UNAUTHORIZED_RAW_READ));
        assertTrue(entries.stream().allMatch(e -> e.inputDigest() != null && e.inputDigest().length() == 64));
        assertTrue(entries.stream().noneMatch(e -> e.rationale().contains("13800001111")),
                "审计依据不得包含原文");
    }

    @Test
    void audit_write_failure_does_not_change_main_outcome() {
        auditStore.injectFailure(true);
        gateway.ingest("crm", "ar-2", Map.of("phone", "13800002222"), null);
        var resp = gateway.access(new AccessRequest("guest", Level.PUBLIC, "ar-2", false));
        LOG.warn("[AUDIT-FAIL] 审计存储故障下主流程结论={} 视图={} 审计条目数={}",
                resp.overallReason(), resp.view(), auditStore.size());
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, resp.overallReason());
        assertEquals("*******2222", resp.view().get("phone"), "审计失败不得影响脱敏结论");
        // 越权结论同样不受影响
        GatewayException ex = assertThrows(GatewayException.class,
                () -> gateway.access(new AccessRequest("guest", Level.PUBLIC, "ar-2", true)));
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, ex.code());
        assertEquals(0, auditStore.size());
    }

    @Test
    void purge_removes_expired_entries_entirely() throws Exception {
        gateway.ingest("crm", "ar-3", Map.of("name", "Zoe"), null);
        int before = auditStore.query("ar-3").size();
        assertEquals(1, before);
        long ttl = properties.getRetention().getAuditTtlMillis();
        properties.getRetention().setAuditTtlMillis(1L);
        Thread.sleep(5);
        int removed = auditStore.purgeExpired(System.currentTimeMillis() - 1L);
        LOG.info("[RETENTION] 清除条目数={}", removed);
        assertTrue(removed >= 1);
        assertTrue(auditStore.query("ar-3").isEmpty(), "过期数据必须整条清除，不得残留 ar-3 条目");
        properties.getRetention().setAuditTtlMillis(ttl);
    }
}
