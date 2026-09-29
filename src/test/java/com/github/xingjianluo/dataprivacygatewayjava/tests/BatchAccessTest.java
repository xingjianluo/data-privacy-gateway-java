package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.BatchService;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批量访问：混合允许/脱敏/拒绝逐条可分；单条失败不拖垮整批；
 * 点名字段裁剪；批量级版本固定与审计。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class BatchAccessTest {

    private static final Logger LOG = LoggerFactory.getLogger(BatchAccessTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired BatchService batchService;

    private void seedRecords() {
        gateway.ingest("crm", "ba-1", Map.of(
                "name", "Alice",
                "phone", "13800001111",
                "idCard", "11010119900101001X",
                "city", "Beijing"), null);
        gateway.ingest("crm", "ba-2", Map.of(
                "name", "Bob",
                "phone", "13800002222",
                "email", "bob@example.com"), null);
    }

    @Test
    void mixed_allow_mask_deny_are_separated_per_item() {
        seedRecords();
        // 同批：高等级（全允许）、低等级普通读（脱敏）、低等级显式取原文（拒绝）
        List<BatchItemRequest> items = List.of(
                new BatchItemRequest("ba-1", null),
                new BatchItemRequest("ba-2", null),
                new BatchItemRequest("ba-2", List.of("phone")));

        BatchAccessResponse high = batchService.accessBatch(
                new AccessRequest("auditor", Level.RESTRICTED, "*", false), items, "ba-mix-1");
        BatchItemResult h1 = high.results().get(0);
        assertTrue(h1.ok());
        assertEquals(ReasonCode.ALLOWED, h1.reason());
        assertEquals("13800001111", h1.view().get("phone"));
        assertEquals("11010119900101001X", h1.view().get("idCard"));
        // 每条都带版本戳与判定依据
        assertTrue(h1.policyVersion() > 0);
        assertTrue(h1.keyVersion() > 0);
        assertTrue(h1.decisions().stream().anyMatch(d -> d.action() == FieldAction.ALLOW));
        LOG.info("[BATCH high] {}", high.results().stream()
                .map(r -> r.recordId() + ":" + r.reason()).toList());

        BatchAccessResponse low = batchService.accessBatch(
                new AccessRequest("guest", Level.PUBLIC, "*", false), items, "ba-mix-2");
        BatchItemResult l1 = low.results().get(0);
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, l1.reason());
        // 同一条内允许与脱敏混排：city 无策略 PUBLIC 放行，phone/idCard 脱敏
        assertEquals("Beijing", l1.view().get("city"));
        assertNotEquals("13800001111", l1.view().get("phone"));
        assertNotEquals("11010119900101001X", l1.view().get("idCard"));
        assertTrue(l1.decisions().stream().allMatch(d -> d.action() == FieldAction.MASK));

        BatchAccessResponse raw = batchService.accessBatch(
                new AccessRequest("guest", Level.PUBLIC, "*", true),
                List.of(new BatchItemRequest("ba-1", List.of("idCard"))), "ba-mix-3");
        BatchItemResult r1 = raw.results().get(0);
        assertTrue(r1.ok());
        // 条目级结论是越范围拒绝，被拒字段不得出现在视图中
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, r1.reason());
        assertFalse(r1.view().containsKey("idCard"));
        assertTrue(r1.decisions().stream().anyMatch(d -> d.action() == FieldAction.DENY));
        LOG.info("[BATCH deny] view={} decisions={}", r1.view(),
                r1.decisions().stream().map(d -> d.rationale()).toList());
    }

    @Test
    void one_bad_record_does_not_fail_the_batch() {
        seedRecords();
        List<BatchItemRequest> items = List.of(
                new BatchItemRequest("ba-1", null),
                new BatchItemRequest("missing-id", null),
                new BatchItemRequest("ba-2", null));
        BatchAccessResponse resp = batchService.accessBatch(
                new AccessRequest("auditor", Level.RESTRICTED, "*", false), items, "ba-isolation");
        assertEquals(3, resp.results().size());
        assertTrue(resp.results().get(0).ok());
        BatchItemResult bad = resp.results().get(1);
        assertFalse(bad.ok());
        assertEquals(ReasonCode.BAD_REQUEST, bad.reason());
        assertNull(bad.view());
        assertNotNull(bad.auditEventId());
        assertTrue(resp.results().get(2).ok());
        LOG.info("[BATCH isolation] {}", resp.results().stream()
                .map(r -> r.recordId() + ":ok=" + r.ok() + ":" + r.reason()).toList());
    }

    @Test
    void field_selection_prunes_unrequested_fields() {
        seedRecords();
        BatchAccessResponse resp = batchService.accessBatch(
                new AccessRequest("auditor", Level.RESTRICTED, "*", false),
                List.of(new BatchItemRequest("ba-1", List.of("phone"))), "ba-fields");
        Map<String, Object> view = resp.results().get(0).view();
        assertEquals("13800001111", view.get("phone"));
        assertFalse(view.containsKey("idCard"));
        assertFalse(view.containsKey("name"));
        assertFalse(view.containsKey("email"));
    }

    @Test
    void empty_batch_is_rejected_at_batch_level() {
        GatewayException ex = assertThrows(GatewayException.class, () ->
                batchService.accessBatch(new AccessRequest("c", Level.PUBLIC, "*", false),
                        new ArrayList<>(), "ba-empty"));
        assertEquals(ReasonCode.BAD_REQUEST, ex.code());
    }

    @Test
    void whole_batch_is_pinned_to_one_policy_and_key_version() {
        seedRecords();
        BatchAccessResponse resp = batchService.accessBatch(
                new AccessRequest("auditor", Level.RESTRICTED, "*", false),
                List.of(new BatchItemRequest("ba-1", null), new BatchItemRequest("ba-2", null)),
                "ba-version");
        long pv = resp.policyVersion();
        int kv = resp.keyVersion() == null ? -1 : resp.keyVersion();
        for (BatchItemResult r : resp.results()) {
            assertEquals(pv, r.policyVersion());
            assertEquals(kv, r.keyVersion() == null ? -1 : r.keyVersion());
        }
    }
}
