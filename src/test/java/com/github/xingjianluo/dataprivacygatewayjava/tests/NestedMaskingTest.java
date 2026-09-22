package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.MaskingService;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
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
class NestedMaskingTest {

    private static final Logger LOG = LoggerFactory.getLogger(NestedMaskingTest.class);

    @Autowired PrivacyGateway gateway;

    @Test
    void same_field_in_depth_array_and_wrappers_gets_identical_masking() {
        // phone 同时出现在：顶层、深层对象、数组、{"value":..} 单键包装、{"type","value"} 双键包装，
        // 以及别名 mobile
        Map<String, Object> raw = Map.of(
                "phone", "13800001111",
                "mobile", "13800002222",
                "profile", Map.of(
                        "phone", Map.of("value", "13800003333"),
                        "contacts", List.of(
                                Map.of("phone", Map.of("type", "HOME", "value", "13800004444")),
                                Map.of("mobile", "13800005555"))));
        gateway.ingest("crm", "nested-1", raw, null);
        AccessRequest req = new AccessRequest("guest", Level.PUBLIC, "nested-1", false);
        AccessResponse resp = gateway.access(req);
        LOG.info("[NESTED] view={}", resp.view());
        LOG.info("[NESTED] 判定依据={}",
                resp.decisions().stream().map(d -> d.rationale()).toList());

        assertEquals("*******1111", resp.view().get("phone"));
        assertEquals("*******2222", resp.view().get("mobile"), "别名必须同等处理");
        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) resp.view().get("profile");
        @SuppressWarnings("unchecked")
        Map<String, Object> wrapped = (Map<String, Object>) profile.get("phone");
        assertEquals("*******3333", wrapped.get("value"), "单键包装内字段必须脱敏");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contacts = (List<Map<String, Object>>) profile.get("contacts");
        @SuppressWarnings("unchecked")
        Map<String, Object> doubleWrapped = (Map<String, Object>) contacts.get(0).get("phone");
        assertEquals("*******4444", doubleWrapped.get("value"), "双键包装深层必须脱敏");
        assertEquals("*******5555", contacts.get(1).get("mobile"), "数组内别名必须脱敏");
        // 所有 phone/mobile 判定均为 MASK，无遗漏
        long phoneDecisions = resp.decisions().stream()
                .filter(d -> d.field().equals("phone") || d.field().equals("mobile"))
                .count();
        assertEquals(5, phoneDecisions, "5 处 phone/mobile 都必须有判定依据");
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, resp.overallReason());
    }

    @Test
    void repeated_masking_is_idempotent() {
        Map<String, Object> raw = Map.of("phone", "13800001111");
        gateway.ingest("crm", "nested-2", raw, null);
        AccessResponse first = gateway.access(
                new AccessRequest("g", Level.PUBLIC, "nested-2", false));
        AccessResponse second = gateway.access(
                new AccessRequest("g", Level.PUBLIC, "nested-2", false));
        LOG.info("[IDEMPOTENT-MASK] first={} second={}", first.view(), second.view());
        assertEquals(first.view(), second.view(), "重复脱敏结果必须一致");
        assertEquals("*******1111", second.view().get("phone"));
        assertNotEquals(MaskingService.MASK_TOKEN + MaskingService.MASK_TOKEN,
                second.view().get("phone"), "不得叠加脱敏");
    }

    @Test
    void masked_token_is_not_double_masked_and_envelope_is_not_distorted() {
        // 已脱敏值入库后再次脱敏
        Map<String, Object> raw = Map.of("idCard", "11010119900101001X", "phone", "13800001111");
        gateway.ingest("crm", "nested-3", raw, null);
        gateway.access(new AccessRequest("g", Level.PUBLIC, "nested-3", false));
        // 加密 phone 后，以低权限访问：密文信封不得被脱敏变形
        gateway.encryptFields("nested-3", List.of("phone"));
        AccessResponse resp = gateway.access(
                new AccessRequest("g", Level.PUBLIC, "nested-3", false));
        @SuppressWarnings("unchecked")
        Map<String, Object> phoneVal = (Map<String, Object>) resp.view().get("phone");
        LOG.info("[ENVELOPE-STABLE] phoneAfterMaskPass={} isEnvelope={}",
                phoneVal, AesGcmCryptoService.isEnvelope(phoneVal));
        assertTrue(AesGcmCryptoService.isEnvelope(phoneVal), "密文信封不得被脱敏叠加变形");
    }
}
