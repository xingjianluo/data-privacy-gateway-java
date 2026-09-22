package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.AuditStore;
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
class AccessDecisionTest {

    private static final Logger LOG = LoggerFactory.getLogger(AccessDecisionTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired AuditStore auditStore;

    private void seed() {
        gateway.ingest("crm", "ad-1", Map.of(
                "name", "Alice",
                "phone", "13800001111",
                "idCard", "11010119900101001X",
                "email", "alice@example.com"), null);
    }

    @Test
    void high_clearance_allows_raw_values() {
        seed();
        AccessRequest req = new AccessRequest("auditor", Level.RESTRICTED, "ad-1", false);
        AccessResponse resp = gateway.access(req);
        LOG.info("[ACCESS-CASE=allow] input caller={} clearance={} | reason={} view={} | 依据={}",
                req.caller(), req.clearance(), resp.overallReason(), resp.view(),
                resp.decisions().stream().map(d -> d.rationale()).toList());
        assertEquals(ReasonCode.ALLOWED, resp.overallReason());
        assertEquals("13800001111", resp.view().get("phone"));
        assertEquals("11010119900101001X", resp.view().get("idCard"));
    }

    @Test
    void low_clearance_is_masked_not_errored() {
        seed();
        AccessRequest req = new AccessRequest("guest", Level.PUBLIC, "ad-1", false);
        AccessResponse resp = gateway.access(req);
        LOG.info("[ACCESS-CASE=mask] input caller={} clearance={} | reason={} view={} | 依据={}",
                req.caller(), req.clearance(), resp.overallReason(), resp.view(),
                resp.decisions().stream().map(d -> d.rationale()).toList());
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, resp.overallReason());
        assertEquals("*******1111", resp.view().get("phone"));
        assertEquals("***MASKED***", resp.view().get("idCard"));
        assertEquals("a***@example.com", resp.view().get("email"));
        assertTrue(resp.decisions().stream().allMatch(d -> d.action() != FieldAction.DENY));
    }

    @Test
    void explicit_raw_request_with_low_clearance_is_denied() {
        seed();
        AccessRequest req = new AccessRequest("guest", Level.PUBLIC, "ad-1", true);
        GatewayException ex = assertThrows(GatewayException.class, () -> gateway.access(req));
        LOG.warn("[ACCESS-CASE=deny] input caller={} clearance={} raw={} | code={} message={}",
                req.caller(), req.clearance(), req.rawRequested(), ex.code(), ex.getMessage());
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, ex.code());
        // 越权必须留下可追溯依据
        boolean audited = auditStore.query("ad-1").stream()
                .anyMatch(e -> e.outcome() == ReasonCode.DENIED_UNAUTHORIZED_RAW_READ
                        && "guest".equals(e.caller()));
        assertTrue(audited, "越权拒绝必须写审计");
    }

    @Test
    void same_input_produces_consistent_decisions_and_pinned_versions() {
        seed();
        AccessResponse a = gateway.access(new AccessRequest("g", Level.PUBLIC, "ad-1", false));
        AccessResponse b = gateway.access(new AccessRequest("g", Level.PUBLIC, "ad-1", false));
        LOG.info("[ACCESS-CASE=consistent] policyV={}/{} keyV={}/{} decisionsA={}",
                a.policyVersion(), b.policyVersion(), a.currentKeyVersion(), b.currentKeyVersion(),
                a.decisions().stream().map(d -> d.rationale()).toList());
        assertEquals(a.view(), b.view());
        assertEquals(a.policyVersion(), b.policyVersion());
        assertEquals(List.copyOf(a.decisions().stream().map(d -> d.rationale()).sorted().toList()),
                List.copyOf(b.decisions().stream().map(d -> d.rationale()).sorted().toList()));
    }
}
