package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessMode;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessResult;
import com.github.xingjianluo.dataprivacygatewayjava.access.DecisionOutcome;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditEvent;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditOutcome;
import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.*;
import com.github.xingjianluo.dataprivacygatewayjava.tests.support.TestFixtures;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 审计与上限：
 * - 审计写入失败不得改变主流程结论；
 * - 每次允许/脱敏/拒绝都有可复现依据，且只存摘要不存原文；
 * - 过期清除后不残留可识别信息；
 * - 规模上限整体拒绝，不留部分结果；耗时上限返回失败且不泄漏中间明文。
 */
class AuditAndLimitsTest {

    private static final Logger log = LoggerFactory.getLogger(AuditAndLimitsTest.class);

    private static final CallerIdentity GUEST = new CallerIdentity("guest",
            Set.of(DataClassification.INTERNAL));
    private static final CallerIdentity AUDITOR = new CallerIdentity("auditor",
            Set.of(DataClassification.values()));

    private TestFixtures.Gateway ingest(TestFixtures.Gateway fx, String id) {
        IngestionResult r = fx.ingestion.ingest(new SourceRecord("crm", id,
                Map.of("customerId", id, "name", "钱七", "idCard", "110101199001011234")));
        assertTrue(r.accepted(), r.violationSummaries().toString());
        fx.records.put(r.record());
        return fx;
    }

    @Test
    void auditWriteFailureDoesNotChangeMainOutcome() {
        TestFixtures.Gateway fx = new TestFixtures.Gateway();
        ingest(fx, "C-AUD-FAIL");
        fx.auditStore.failNextWrite(); // 下一次审计写入强制失败

        AccessResult result = fx.gateway.access(GUEST, "C-AUD-FAIL", AccessMode.NORMAL);
        assertEquals(DecisionOutcome.MASKED, result.overall(), "审计失败不得改变主流程结论");
        assertNotNull(result.data(), "脱敏数据必须照常返回");
        assertEquals(1, fx.auditStore.failedWriteCount(), "失败必须被计数但不外抛");
        log.info("[判定依据] 审计写失败后 overall 仍={}, failedWrites={}",
                result.overall(), fx.auditStore.failedWriteCount());
    }

    @Test
    void everyOutcomeIsAuditedWithReproducibleSummaryAndNoRawValues() {
        TestFixtures.Gateway fx = new TestFixtures.Gateway();
        ingest(fx, "C-AUD-ALL");

        fx.gateway.access(AUDITOR, "C-AUD-ALL", AccessMode.NORMAL);   // ALLOW
        fx.gateway.access(GUEST, "C-AUD-ALL", AccessMode.NORMAL);     // MASK
        fx.gateway.access(GUEST, "C-AUD-ALL", AccessMode.RAW);        // DENY

        List<AuditEvent> events = fx.auditStore.findByRecord("C-AUD-ALL");
        assertEquals(3, events.size());
        assertEquals(List.of(AuditOutcome.ALLOW, AuditOutcome.MASK, AuditOutcome.DENY),
                events.stream().map(AuditEvent::outcome).toList());
        for (AuditEvent e : events) {
            assertTrue(e.inputSummary().startsWith("sha256:"), "输入摘要可复现且不含原文");
            assertFalse(e.fieldBasis().toString().contains("110101199001011234"),
                    "审计依据中不得出现原始敏感值");
            assertFalse(e.fieldBasis().toString().contains("钱七"));
        }
        // 摘要稳定性：同一调用方对同一记录的重复访问摘要必须完全一致（可复现）
        fx.gateway.access(GUEST, "C-AUD-ALL", AccessMode.NORMAL);
        List<AuditEvent> guestEvents = fx.auditStore.findByRecord("C-AUD-ALL").stream()
                .filter(e -> e.callerId().equals("guest")).toList();
        assertTrue(guestEvents.size() >= 2);
        assertEquals(guestEvents.get(0).inputSummary(), guestEvents.get(1).inputSummary(),
                "相同输入（调用方+记录+字段集）的摘要必须稳定可复现");
        // 不同调用方摘要允许不同（调用方身份是摘要输入的一部分）
        assertNotEquals(events.get(0).inputSummary(), events.get(1).inputSummary());
        log.info("[判定依据] guest 重复访问摘要一致={}, auditor 与 guest 摘要可区分={}",
                guestEvents.get(0).inputSummary().equals(guestEvents.get(1).inputSummary()),
                !events.get(0).inputSummary().equals(events.get(1).inputSummary()));
    }

    @Test
    void expiredAuditIsPurgedWithoutResidue() {
        TestFixtures.Gateway fx = new TestFixtures.Gateway();
        ingest(fx, "C-RET");
        fx.gateway.access(GUEST, "C-RET", AccessMode.NORMAL);
        AuditEvent event = fx.auditStore.findByRecord("C-RET").get(0);

        // 时钟前进到事件时间 31 天后（留存 30 天）
        Instant eventTime = event.timestamp();
        Instant future = eventTime.plusSeconds(31L * 24 * 60 * 60);
        fx.auditStore.setClock(Clock.fixed(future, ZoneOffset.UTC));
        int removed = fx.auditStore.purgeExpired(future);
        assertEquals(1, removed);
        assertTrue(fx.auditStore.findByRecord("C-RET").isEmpty(), "过期审计必须被物理清除");
        assertTrue(fx.auditStore.all().stream().noneMatch(e -> e.eventId().equals(event.eventId())),
                "清除后不得残留可识别记录");
        log.info("[输入摘要] 事件时间={}, 留存30天; [判定依据] purge removed=1, storeSize={}",
                event.timestamp(), fx.auditStore.size());
    }

    @Test
    void leafLimitIsEnforcedWithoutPartialResult() {
        GatewayProperties p = TestFixtures.properties();
        p.setMaxLeavesPerResponse(2); // 仅允许 2 个叶子
        TestFixtures.Gateway fx = new TestFixtures.Gateway(p);
        ingest(fx, "C-LIMIT");

        AccessResult result = fx.gateway.access(AUDITOR, "C-LIMIT", AccessMode.NORMAL);
        assertEquals(DecisionOutcome.DENIED, result.overall());
        assertNull(result.data(), "超规模必须整体拒绝，不返回部分处理结果");
        AuditEvent e = fx.auditStore.findByRecord("C-LIMIT").get(0);
        assertTrue(e.reason().contains("LIMIT_EXCEEDED"), "拒绝原因可追溯: " + e.reason());
        log.info("[判定依据] leaves=3 > limit=2 -> overall=DENIED, data=null, reason={}", e.reason());
    }

    @Test
    void deadlineExceededFailsWithoutLeakingIntermediatePlaintext() {
        GatewayProperties p = TestFixtures.properties();
        p.setProcessingTimeoutMillis(1); // 1ms：大树遍历必然在某个叶子处超时
        p.setMaxNodesPerRecord(100_000);
        p.setMaxLeavesPerResponse(100_000);
        p.setMaxArrayLength(100_000);
        TestFixtures.Gateway fx = new TestFixtures.Gateway(p);

        // 构造一棵约 4 万叶子的树：records 为标量数组（路径归一为 idCard，落库加密，
        // 正常路径会逐个解密），触发中途超时
        java.util.List<String> items = new java.util.ArrayList<>();
        for (int i = 0; i < 40_000; i++) {
            items.add(String.format("ID%018d", i));
        }
        java.util.Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("customerId", "C-BIG");
        payload.put("name", "root-name");
        payload.put("idCard", "110101199001011234");
        payload.put("idCards", items);
        IngestionResult r = fx.ingestion.ingest(new SourceRecord("crm", "C-BIG", payload));
        assertTrue(r.accepted(), r.violationSummaries().toString());
        fx.records.put(r.record());

        AccessResult result = fx.gateway.access(AUDITOR, "C-BIG", AccessMode.NORMAL);
        // 极短时限下必须在中途失败：结论 FAILED，且结果数据整体丢弃（可能已有叶子被解密）
        assertEquals(DecisionOutcome.FAILED, result.overall());
        assertNull(result.data(), "超时后不得残留任何部分处理结果/已解密中间值");
        AuditEvent e = fx.auditStore.findByRecord("C-BIG").get(0);
        assertTrue(e.reason().contains("DEADLINE_EXCEEDED"), "失败原因可追溯: " + e.reason());
        log.info("[输入摘要] ~40000 叶子, timeout=1ms; [判定依据] overall=FAILED, data=null, reason={}",
                e.reason());
    }
}
