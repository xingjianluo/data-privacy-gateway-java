package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.model.FieldSpec;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestReport;
import com.github.xingjianluo.dataprivacygatewayjava.model.JsonType;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.RecordSchema;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.util.Digests;
import com.github.xingjianluo.dataprivacygatewayjava.util.JsonCodec;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class IngestValidationTest {

    private static final Logger LOG = LoggerFactory.getLogger(IngestValidationTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired RecordStore recordStore;

    private RecordSchema schema() {
        return new RecordSchema("user", List.of(
                new FieldSpec("name", JsonType.STRING, true),
                new FieldSpec("age", JsonType.NUMBER, false),
                new FieldSpec("phones", JsonType.ARRAY, false)));
    }

    private void logInput(String caseName, Object input) {
        LOG.info("[INGEST-CASE={}] inputSummary bytes={} sha256={}",
                caseName, JsonCodec.estimatedBytes(input), Digests.sha256Hex(JsonCodec.canonical(input)));
    }

    @Test
    void missing_required_field_is_rejected_with_distinct_code() {
        Map<String, Object> raw = Map.of("age", 30);
        logInput("missing", raw);
        IngestReport report = gateway.ingest("srcA", "iv-missing", raw, schema());
        LOG.info("[INGEST-CASE=missing] accepted={} reason={} fieldRejections={}",
                report.accepted(), report.reason(), report.fieldRejections());
        assertFalse(report.accepted());
        assertEquals(ReasonCode.REJECT_MISSING_FIELD, report.reason());
        assertEquals(ReasonCode.REJECT_MISSING_FIELD, report.fieldRejections().get("name"));
        assertNull(recordStore.get("iv-missing"), "拒绝记录不得落库");
    }

    @Test
    void type_mismatch_is_distinguished_from_missing() {
        Map<String, Object> raw = Map.of("name", 12345, "age", "not-a-number");
        logInput("typeMismatch", raw);
        IngestReport report = gateway.ingest("srcA", "iv-type", raw, schema());
        LOG.info("[INGEST-CASE=typeMismatch] accepted={} reason={} fieldRejections={}",
                report.accepted(), report.reason(), report.fieldRejections());
        assertFalse(report.accepted());
        assertEquals(ReasonCode.REJECT_TYPE_MISMATCH, report.fieldRejections().get("name"));
        assertEquals(ReasonCode.REJECT_TYPE_MISMATCH, report.fieldRejections().get("age"));
    }

    @Test
    void oversized_record_is_rejected() {
        Map<String, Object> raw = Map.of("name", "x".repeat(20_000));
        logInput("oversized", raw);
        IngestReport report = gateway.ingest("srcA", "iv-size", raw, schema());
        LOG.info("[INGEST-CASE=oversized] accepted={} reason={}", report.accepted(), report.reason());
        assertFalse(report.accepted());
        assertEquals(ReasonCode.REJECT_SIZE_EXCEEDED, report.reason());
    }

    @Test
    void string_too_long_is_distinct_code() {
        Map<String, Object> raw = Map.of("name", "x".repeat(2_000));
        logInput("stringLong", raw);
        IngestReport report = gateway.ingest("srcA", "iv-str", raw, schema());
        LOG.info("[INGEST-CASE=stringLong] reason={} rejections={}",
                report.reason(), report.fieldRejections());
        assertEquals(ReasonCode.REJECT_STRING_TOO_LONG, report.fieldRejections().get("$.name"));
    }

    @Test
    void valid_multi_source_records_normalize_to_same_model() {
        Map<String, Object> src1 = Map.of("name", "Alice", "age", 29,
                "phones", List.of("1", "2"));
        Map<String, Object> src2 = new LinkedHashMap<>();
        src2.put("name", "Bob");
        src2.put("age", 41);
        src2.put("extra", Map.of("k", "v"));
        logInput("multi1", src1);
        logInput("multi2", src2);
        IngestReport r1 = gateway.ingest("crm", "iv-ok-1", src1, schema());
        IngestReport r2 = gateway.ingest("erp", "iv-ok-2", src2, schema());
        LOG.info("[INGEST-CASE=multi] r1={}/{} r2={}/{}", r1.accepted(), r1.reason(),
                r2.accepted(), r2.reason());
        assertTrue(r1.accepted() && r2.accepted());
        assertEquals("crm", recordStore.get("iv-ok-1").source());
        assertEquals("erp", recordStore.get("iv-ok-2").source());
    }
}
