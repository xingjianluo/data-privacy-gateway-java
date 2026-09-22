package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestReport;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.RecordStore;
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

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class LimitGuardTest {

    private static final Logger LOG = LoggerFactory.getLogger(LimitGuardTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired RecordStore recordStore;
    @Autowired GatewayProperties properties;

    @Test
    void array_oversize_rejected_in_reject_mode_and_no_partial_state() {
        properties.getLimits().setMode(LimitMode.REJECT);
        List<String> phones = new ArrayList<>();
        for (int i = 0; i < 250; i++) {
            phones.add("138%08d".formatted(i));
        }
        Map<String, Object> raw = Map.of("phones", phones);
        IngestReport report = gateway.ingest("crm", "lg-1", raw, null);
        LOG.info("[LIMIT-CASE=arrayReject] accepted={} reason={} rejections={}",
                report.accepted(), report.reason(), report.fieldRejections());
        assertFalse(report.accepted());
        assertEquals(ReasonCode.REJECT_ARRAY_TOO_LARGE, report.fieldRejections().get("$.phones"));
        assertNull(recordStore.get("lg-1"), "拒绝后不得残留部分处理状态");
    }

    @Test
    void array_oversize_truncated_in_truncate_mode() {
        properties.getLimits().setMode(LimitMode.TRUNCATE);
        try {
            List<String> phones = new ArrayList<>();
            for (int i = 0; i < 250; i++) {
                phones.add("138%08d".formatted(i));
            }
            IngestReport report = gateway.ingest("crm", "lg-2", Map.of("phones", phones), null);
            LOG.info("[LIMIT-CASE=arrayTruncate] accepted={} reason={}",
                    report.accepted(), report.reason());
            assertTrue(report.accepted());
            assertEquals(ReasonCode.TRUNCATED_BY_LIMIT, report.reason());
            @SuppressWarnings("unchecked")
            List<Object> stored = (List<Object>) recordStore.get("lg-2").data().get("phones");
            assertEquals(properties.getLimits().getTruncateArrayTo(), stored.size());
        } finally {
            properties.getLimits().setMode(LimitMode.REJECT);
        }
    }

    @Test
    void depth_exceeded_is_rejected_or_truncated() {
        properties.getLimits().setMode(LimitMode.REJECT);
        Map<String, Object> deep = Map.of("a", Map.of("b", Map.of("c",
                Map.of("d", Map.of("e", Map.of("f", Map.of("g", Map.of("h", "deep"))))))));
        IngestReport report = gateway.ingest("crm", "lg-3", deep, null);
        LOG.info("[LIMIT-CASE=depth] accepted={} reason={} rejections={}",
                report.accepted(), report.reason(), report.fieldRejections());
        assertFalse(report.accepted());
        assertTrue(report.fieldRejections().containsValue(ReasonCode.REJECT_DEPTH_EXCEEDED));
    }

    @Test
    void access_timeout_is_reported_with_controlled_reason() {
        gateway.ingest("crm", "lg-4", Map.of("name", "A"), null);
        long saved = properties.getLimits().getMaxElapsedMillis();
        properties.getLimits().setMaxElapsedMillis(0L);
        try {
            GatewayException ex = assertThrows(GatewayException.class, () -> gateway.access(
                    new AccessRequest("g", Level.PUBLIC, "lg-4", false)));
            LOG.warn("[LIMIT-CASE=timeout] code={} message={}", ex.code(), ex.getMessage());
            assertEquals(ReasonCode.REQUEST_TIMEOUT, ex.code());
        } finally {
            properties.getLimits().setMaxElapsedMillis(saved);
        }
    }

    @Test
    void failed_access_never_returns_partial_decrypted_view() {
        // 越权访问时返回体整体丢弃
        gateway.ingest("crm", "lg-5",
                Map.of("phone", "13800001111", "idCard", "11010119900101001X"), null);
        GatewayException ex = assertThrows(GatewayException.class, () -> gateway.access(
                new AccessRequest("g", Level.PUBLIC, "lg-5", true)));
        LOG.warn("[LIMIT-CASE=noPartial] code={}", ex.code());
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, ex.code());
        // 底层记录仍是原值，未被部分脱敏写回
        assertEquals("13800001111", recordStore.get("lg-5").data().get("phone"));
    }
}
