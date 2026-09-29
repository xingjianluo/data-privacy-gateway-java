package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
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
class BatchAccessTest {

    private static final Logger LOG = LoggerFactory.getLogger(BatchAccessTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired AuditStore auditStore;
    @Autowired GatewayProperties properties;

    private void seed() {
        gateway.ingest("crm", "ba-1", Map.of(
                "name", "Alice",
                "phone", "13800001111",
                "city", "Beijing"), null);
        gateway.ingest("crm", "ba-2", Map.of(
                "name", "Bob",
                "phone", "13900002222",
                "city", "Shanghai"), null);
    }

    @Test
    void mixed_allow_mask_deny_per_item_in_one_batch() {
        seed();
        // raw=true + PUBLIC 调用方：只点名 city 的条目 ALLOW；点名 phone 的条目 DENY；缺记录条目 BAD_REQUEST
        BatchAccessRequest req = new BatchAccessRequest("guest", Level.PUBLIC, true, List.of(
                new BatchItem("ba-1", List.of("city")),
                new BatchItem("ba-2", List.of("phone")),
                new BatchItem("ba-missing", List.of())));
        BatchResponse resp = gateway.batchAccess(req);
        LOG.info("[BATCH-CASE=mixed] results={}",
                resp.results().stream().map(r -> r.recordId() + "->" + r.outcome()).toList());

        assertEquals(3, resp.results().size());
        BatchItemResult allow = resp.results().get(0);
        BatchItemResult deny = resp.results().get(1);
        BatchItemResult missing = resp.results().get(2);

        assertEquals(ReasonCode.ALLOWED, allow.outcome());
        assertEquals("Beijing", allow.view().get("city"));
        assertFalse(allow.decisions().isEmpty(), "每条都要带判定依据");
        assertTrue(allow.policyVersion() > 0 && allow.keyVersion() > 0,
                "每条都要带当时生效的策略与密钥版本");

        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, deny.outcome());
        assertNull(deny.view(), "被拒绝的条目不返回任何字段视图");
        assertTrue(deny.decisions().stream().anyMatch(d -> d.action() == FieldAction.DENY));

        assertEquals(ReasonCode.BAD_REQUEST, missing.outcome());
        assertNull(missing.view());

        // 单条拒绝/失败不把整批带崩：ALLOW 条目结论不受其他条目影响
        assertEquals("Beijing", allow.view().get("city"));

        // 拒绝条目留下可追溯审计
        boolean audited = auditStore.query("ba-2").stream()
                .anyMatch(e -> e.outcome() == ReasonCode.DENIED_UNAUTHORIZED_RAW_READ
                        && "guest".equals(e.caller()));
        assertTrue(audited, "批量中的拒绝条目必须写审计");
    }

    @Test
    void mask_and_allow_mixed_when_not_raw() {
        seed();
        // raw=false + PUBLIC：phone 条目脱敏、city 条目放行，同批共存
        BatchAccessRequest req = new BatchAccessRequest("guest", Level.PUBLIC, false, List.of(
                new BatchItem("ba-1", List.of("phone")),
                new BatchItem("ba-2", List.of("city"))));
        BatchResponse resp = gateway.batchAccess(req);
        LOG.info("[BATCH-CASE=maskMix] results={}",
                resp.results().stream().map(r -> r.recordId() + "->" + r.outcome()).toList());
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, resp.results().get(0).outcome());
        assertEquals("*******1111", resp.results().get(0).view().get("phone"));
        assertEquals(ReasonCode.ALLOWED, resp.results().get(1).outcome());
        assertEquals("Shanghai", resp.results().get(1).view().get("city"));
    }

    @Test
    void field_selection_limits_view_to_named_fields() {
        seed();
        BatchAccessRequest req = new BatchAccessRequest("auditor", Level.RESTRICTED, false, List.of(
                new BatchItem("ba-1", List.of("name"))));
        BatchResponse resp = gateway.batchAccess(req);
        BatchItemResult r = resp.results().get(0);
        LOG.info("[BATCH-CASE=fieldSelect] view={}", r.view());
        assertEquals(Map.of("name", "Alice"), r.view(), "只返回点名字段");
    }

    @Test
    void batch_size_limit_reject_mode_fails_whole_batch_with_audit() {
        seed();
        properties.getLimits().setMode(LimitMode.REJECT);
        properties.getBatch().setMaxItems(2);
        try {
            BatchAccessRequest req = new BatchAccessRequest("auditor", Level.RESTRICTED, false, List.of(
                    new BatchItem("ba-1", List.of()),
                    new BatchItem("ba-2", List.of()),
                    new BatchItem("ba-1", List.of())));
            GatewayException ex = assertThrows(GatewayException.class, () -> gateway.batchAccess(req));
            LOG.warn("[BATCH-CASE=limitReject] code={} message={}", ex.code(), ex.getMessage());
            assertEquals(ReasonCode.BATCH_LIMIT_EXCEEDED, ex.code());
            boolean audited = auditStore.all().stream()
                    .anyMatch(e -> e.outcome() == ReasonCode.BATCH_LIMIT_EXCEEDED);
            assertTrue(audited, "超限拒绝必须写审计");
        } finally {
            properties.getBatch().setMaxItems(100);
        }
    }

    @Test
    void batch_size_limit_truncate_mode_truncates_and_marks() {
        seed();
        properties.getLimits().setMode(LimitMode.TRUNCATE);
        properties.getBatch().setMaxItems(1);
        try {
            BatchAccessRequest req = new BatchAccessRequest("auditor", Level.RESTRICTED, false, List.of(
                    new BatchItem("ba-1", List.of("city")),
                    new BatchItem("ba-2", List.of("city"))));
            BatchResponse resp = gateway.batchAccess(req);
            LOG.info("[BATCH-CASE=limitTruncate] requested={} returned={} truncated={}",
                    resp.requestedCount(), resp.results().size(), resp.truncated());
            assertTrue(resp.truncated(), "截断必须显式标记");
            assertEquals(2, resp.requestedCount());
            assertEquals(1, resp.results().size());
        } finally {
            properties.getBatch().setMaxItems(100);
            properties.getLimits().setMode(LimitMode.REJECT);
        }
    }

    @Test
    void batch_timeout_fails_whole_batch_without_partial_results() {
        seed();
        properties.getLimits().setMaxElapsedMillis(-1);
        try {
            BatchAccessRequest req = new BatchAccessRequest("auditor", Level.RESTRICTED, false, List.of(
                    new BatchItem("ba-1", List.of()),
                    new BatchItem("ba-2", List.of())));
            GatewayException ex = assertThrows(GatewayException.class, () -> gateway.batchAccess(req));
            LOG.warn("[BATCH-CASE=timeout] code={} message={}", ex.code(), ex.getMessage());
            assertEquals(ReasonCode.REQUEST_TIMEOUT, ex.code());
            // 超时抛异常：调用方拿不到任何部分结果（无返回值可言），重试幂等因读取无副作用
        } finally {
            properties.getLimits().setMaxElapsedMillis(1000);
        }
    }
}
