package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 点名字段深层匹配：嵌套子对象、数组元素、{@code {"value":x}} / {@code {"type","value"}}
 * 包装、别名键下的逻辑字段都必须被识别、返回并带独立判定依据；不存在与越授权范围
 * 必须如实体现；批量访问与批量明文导出两条入口对同一数据同一批点名字段结论一致。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class NamedFieldSelectionTest {

    private static final Logger LOG = LoggerFactory.getLogger(NamedFieldSelectionTest.class);

    @Autowired PrivacyGateway gateway;

    /**
     * 复杂结构记录（种子策略：phone←mobile/telephone CONFIDENTIAL/TAIL4；
     * idCard←identityNo RESTRICTED/FULL；email←mail INTERNAL/EMAIL；name←fullName INTERNAL）。
     * phone 逻辑字段同时出现在：嵌套对象深层（别名 mobile）、单键包装、双键包装、
     * 数组对象别名键、数组元素深层别名(telephone)、phone 父键下的包装数组。
     */
    private void seedComplex(String recordId) {
        Map<String, Object> raw = Map.of(
                "name", "Alice",
                "city", "Beijing",
                "profile", Map.of(
                        "mobile", "13800002222",
                        "contact", Map.of(
                                "phone", Map.of("value", "13800003333")),
                        "contacts", List.of(
                                Map.of("phone", Map.of("type", "HOME", "value", "13800004444")),
                                Map.of("mobile", "13800005555"),
                                Map.of("profile", Map.of("telephone", "13800006666"))),
                        "phone", List.of(
                                Map.of("value", "13800007777"),
                                Map.of("type", "WORK", "value", "13800008888"))));
        gateway.ingest("crm", recordId, raw, null);
    }

    /** phone 逻辑字段在复杂记录中的 7 处出现路径（与裁剪后视图严格对应）。 */
    private static final List<String> PHONE_PATHS = List.of(
            "$.profile.mobile",
            "$.profile.contact.phone",
            "$.profile.contacts[0].phone",
            "$.profile.contacts[1].mobile",
            "$.profile.contacts[2].profile.telephone",
            "$.profile.phone[0]",
            "$.profile.phone[1]");

    private static void assertPhoneDecisions(BatchItemResult r, FieldAction action,
                                             ReasonCode reason) {
        LOG.info("[NAMED] record={} outcome={} view={}", r.recordId(), r.outcome(), r.view());
        LOG.info("[NAMED] decisions={}",
                r.decisions().stream().map(FieldDecision::rationale).toList());
        assertEquals(PHONE_PATHS.size(),
                r.decisions().stream().filter(d -> d.path() != null && d.path().startsWith("$.")).count(),
                "7 处 phone 出现都要有判定依据");
        for (String path : PHONE_PATHS) {
            FieldDecision d = r.decisions().stream()
                    .filter(x -> path.equals(x.path()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("缺少判定依据 path=" + path));
            assertEquals(action, d.action(), "path=" + path + " 动作不符");
            assertEquals(reason, d.reason(), "path=" + path + " 原因码不符");
            assertTrue(Set.of("phone", "mobile", "telephone").contains(d.field()),
                    "field 应为命中的本地逻辑名（别名键保留别名、包装/父键为 phone），实际="
                            + d.field());
            assertEquals(Level.CONFIDENTIAL, d.requiredLevel(), "依据必须带所需持证等级");
            assertTrue(d.policyVersion() > 0, "依据必须带当时生效的策略版本");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> profileOf(BatchItemResult r) {
        return (Map<String, Object>) r.view().get("profile");
    }

    @SuppressWarnings("unchecked")
    private static List<Object> contactsOf(BatchItemResult r) {
        return (List<Object>) profileOf(r).get("contacts");
    }

    // ------------------------------------------------------------------
    // 批量访问：嵌套 / 数组 / 包装 / 别名
    // ------------------------------------------------------------------

    @Test
    void batch_access_named_phone_found_everywhere_high_clearance() {
        seedComplex("nsel-1");
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "auditor", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-1", List.of("phone")))));
        BatchItemResult r = resp.results().get(0);
        assertEquals(ReasonCode.ALLOWED, r.outcome(), "全部命中且允许时必须报 ALLOWED");
        assertNull(r.message());
        assertPhoneDecisions(r, FieldAction.ALLOW, ReasonCode.ALLOWED);

        Map<String, Object> profile = profileOf(r);
        @SuppressWarnings("unchecked")
        Map<String, Object> contact = (Map<String, Object>) profile.get("contact");
        assertEquals("13800002222", profile.get("mobile"), "深层别名键下的字段必须返回");
        assertEquals("13800003333", ((Map<?, ?>) contact.get("phone")).get("value"),
                "单键包装内字段必须返回");
        List<Object> contacts = contactsOf(r);
        assertEquals("13800004444",
                ((Map<?, ?>) ((Map<?, ?>) contacts.get(0)).get("phone")).get("value"),
                "双键包装深层字段必须返回");
        assertEquals("13800005555", ((Map<?, ?>) contacts.get(1)).get("mobile"),
                "数组元素别名键字段必须返回");
        @SuppressWarnings("unchecked")
        Map<String, Object> third = (Map<String, Object>) contacts.get(2);
        assertEquals("13800006666",
                ((Map<?, ?>) third.get("profile")).get("telephone"),
                "数组元素深层别名键(telephone)字段必须返回");
        @SuppressWarnings("unchecked")
        List<Object> phoneWrappers = (List<Object>) profile.get("phone");
        assertEquals("13800007777", ((Map<?, ?>) phoneWrappers.get(0)).get("value"),
                "phone 父键数组中的单键包装元素必须返回");
        assertEquals("13800008888", ((Map<?, ?>) phoneWrappers.get(1)).get("value"),
                "phone 父键数组中的双键包装元素必须返回");

        assertFalse(r.view().containsKey("name"), "没点名的顶层字段不能带出");
        assertFalse(r.view().containsKey("city"));
        assertTrue(r.policyVersion() > 0 && r.keyVersion() > 0,
                "每条结果都钉在批次开始时固定的策略与密钥版本上");
    }

    @Test
    void batch_access_named_phone_masked_per_occurrence_low_clearance() {
        seedComplex("nsel-2");
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "guest", Level.PUBLIC, false,
                List.of(new BatchItem("nsel-2", List.of("phone")))));
        BatchItemResult r = resp.results().get(0);
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, r.outcome(),
                "低权限普通读取：每一处 phone 都脱敏，条目标 MASKED");
        assertPhoneDecisions(r, FieldAction.MASK, ReasonCode.MASKED_INSUFFICIENT_CLEARANCE);

        Map<String, Object> profile = profileOf(r);
        @SuppressWarnings("unchecked")
        Map<String, Object> contact = (Map<String, Object>) profile.get("contact");
        assertEquals("*******2222", profile.get("mobile"));
        assertEquals("*******3333", ((Map<?, ?>) contact.get("phone")).get("value"));
        List<Object> contacts = contactsOf(r);
        assertEquals("*******4444",
                ((Map<?, ?>) ((Map<?, ?>) contacts.get(0)).get("phone")).get("value"));
        assertEquals("*******5555", ((Map<?, ?>) contacts.get(1)).get("mobile"));
        @SuppressWarnings("unchecked")
        Map<String, Object> maskedThird = (Map<String, Object>) contacts.get(2);
        assertEquals("*******6666",
                ((Map<?, ?>) maskedThird.get("profile")).get("telephone"));
        @SuppressWarnings("unchecked")
        List<Object> maskedWrappers = (List<Object>) profile.get("phone");
        assertEquals("*******7777", ((Map<?, ?>) maskedWrappers.get(0)).get("value"));
        assertEquals("*******8888", ((Map<?, ?>) maskedWrappers.get(1)).get("value"));
        // 未点名字段依旧不出现
        assertFalse(r.view().containsKey("name"));
    }

    @Test
    void batch_access_named_phone_raw_denied_low_clearance() {
        seedComplex("nsel-3");
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "guest", Level.PUBLIC, true,
                List.of(new BatchItem("nsel-3", List.of("phone")))));
        BatchItemResult r = resp.results().get(0);
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, r.outcome());
        assertNull(r.view(), "越权取原文的条目不返回任何字段视图");
        assertTrue(r.decisions().stream().allMatch(d -> d.action() == FieldAction.DENY));
        assertTrue(r.decisions().size() >= 7, "深层每一处 phone 都要有拒绝依据");
    }

    @Test
    void batch_access_alias_name_selects_same_logical_field() {
        // 用别名 mobile 点名与用 phone 点名等价
        seedComplex("nsel-4");
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "auditor", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-4", List.of("mobile")))));
        BatchItemResult r = resp.results().get(0);
        assertEquals(ReasonCode.ALLOWED, r.outcome());
        assertPhoneDecisions(r, FieldAction.ALLOW, ReasonCode.ALLOWED);
        assertFalse(r.view().containsKey("name"));
    }

    @Test
    void batch_access_missing_field_is_reported_not_silently_allowed() {
        seedComplex("nsel-5");
        // idCard 完全不存在；phone 存在 → 部分缺失也要明确体现，不能空结果报 ALLOW
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "auditor", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-5", List.of("idCard", "phone")))));
        BatchItemResult r = resp.results().get(0);
        LOG.info("[NAMED-MISSING] outcome={} message={} view={}", r.outcome(), r.message(), r.view());
        assertEquals(ReasonCode.FIELD_NOT_FOUND, r.outcome(),
                "点名字段不存在时不得报 ALLOWED");
        assertNotNull(r.view(), "存在的字段仍应返回，缺失的字段单独标记");
        assertTrue(profileOf(r).containsKey("mobile"), "取得到的 phone 不应被缺失字段连累");

        FieldDecision nf = r.decisions().stream()
                .filter(d -> d.action() == FieldAction.NOT_FOUND)
                .findFirst()
                .orElseThrow(() -> new AssertionError("必须有 NOT_FOUND 判定依据"));
        assertEquals("idCard", nf.field());
        assertEquals(ReasonCode.FIELD_NOT_FOUND, nf.reason());
        assertTrue(nf.policyVersion() > 0);
        assertNotNull(r.message());

        // 全部点名字段都不存在：视图为空、结论仍是 FIELD_NOT_FOUND 而非 ALLOWED
        BatchResponse none = gateway.batchAccess(new BatchAccessRequest(
                "auditor", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-5", List.of("idCard")))));
        BatchItemResult nr = none.results().get(0);
        assertEquals(ReasonCode.FIELD_NOT_FOUND, nr.outcome());
        assertTrue(nr.view().isEmpty(), "字段全部取不到时视图为空，但不能报允许");
    }

    @Test
    void batch_access_one_bad_record_does_not_affect_other_items() {
        seedComplex("nsel-6");
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "auditor", Level.RESTRICTED, false, List.of(
                        new BatchItem("nsel-6", List.of("idCard")),       // 字段缺失
                        new BatchItem("nsel-missing", List.of("phone")), // 记录不存在
                        new BatchItem("nsel-6", List.of("phone")))));    // 正常深层命中
        assertEquals(ReasonCode.FIELD_NOT_FOUND, resp.results().get(0).outcome());
        assertEquals(ReasonCode.BAD_REQUEST, resp.results().get(1).outcome());
        assertEquals(ReasonCode.ALLOWED, resp.results().get(2).outcome());
        assertEquals("13800002222", profileOf(resp.results().get(2)).get("mobile"));
    }

    // ------------------------------------------------------------------
    // 批量明文导出：同一深层口径 + 两入口结论一致 + 授权范围
    // ------------------------------------------------------------------

    @Test
    void batch_export_named_nested_phone_returns_plaintext_with_decisions() {
        seedComplex("nsel-7");
        gateway.encryptFields("nsel-7", List.of("phone"));
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nsel-7"),
                Set.of("phone", "name"), 60_000);
        BatchResponse resp = gateway.batchExport(grant.grantId(), new BatchAccessRequest(
                "ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-7", List.of("phone")))));
        BatchItemResult r = resp.results().get(0);
        LOG.info("[NAMED-EXPORT] outcome={} view={}", r.outcome(), r.view());
        assertEquals(ReasonCode.ALLOWED, r.outcome());
        assertPhoneDecisions(r, FieldAction.ALLOW, ReasonCode.ALLOWED);
        // 嵌套/数组/包装内的 phone 都正确返回（别名为明文原值，phone 键信封被解开）
        Map<String, Object> profile = profileOf(r);
        @SuppressWarnings("unchecked")
        Map<String, Object> contact = (Map<String, Object>) profile.get("contact");
        assertEquals("13800002222", profile.get("mobile"));
        assertEquals("13800003333", ((Map<?, ?>) contact.get("phone")).get("value"),
                "嵌套包装内密文信封必须解开为明文");
        List<Object> contacts = contactsOf(r);
        assertEquals("13800004444",
                ((Map<?, ?>) ((Map<?, ?>) contacts.get(0)).get("phone")).get("value"),
                "数组元素双键包装内密文必须解开");
        assertEquals("13800005555", ((Map<?, ?>) contacts.get(1)).get("mobile"));
        @SuppressWarnings("unchecked")
        Map<String, Object> third = (Map<String, Object>) contacts.get(2);
        assertEquals("13800006666",
                ((Map<?, ?>) third.get("profile")).get("telephone"));
        @SuppressWarnings("unchecked")
        List<Object> phoneWrappers = (List<Object>) profile.get("phone");
        assertEquals("13800007777", ((Map<?, ?>) phoneWrappers.get(0)).get("value"),
                "phone 父键数组内包装信封必须解开");
        assertEquals("13800008888", ((Map<?, ?>) phoneWrappers.get(1)).get("value"));
        // 明文不落库：库内 phone 包装位仍是密文信封
        @SuppressWarnings("unchecked")
        Map<String, Object> stored =
                (Map<String, Object>) gateway.access(
                        new com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest(
                                "ops", Level.RESTRICTED, "nsel-7", false)).view().get("profile");
        @SuppressWarnings("unchecked")
        List<Object> storedWrappers = (List<Object>) stored.get("phone");
        assertTrue(AesGcmCryptoService.isEnvelope(((Map<?, ?>) storedWrappers.get(0)).get("value")),
                "导出明文只存在于返回视图，数组包装内密文不得落库");
        assertTrue(AesGcmCryptoService.isEnvelope(
                        ((Map<?, ?>) ((Map<?, ?>) stored.get("contact")).get("phone")).get("value")),
                "嵌套包装内密文同样不得落库");
    }

    @Test
    void batch_access_and_export_agree_on_same_named_fields() {
        seedComplex("nsel-8");
        gateway.encryptFields("nsel-8", List.of("phone"));
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nsel-8"),
                Set.of("phone", "idCard"), 60_000);

        // 低权限（PUBLIC，raw=false）：两入口都必须逐处 MASK，口径一致
        BatchAccessRequest maskReq = new BatchAccessRequest("ops", Level.PUBLIC, false,
                List.of(new BatchItem("nsel-8", List.of("phone"))));
        BatchItemResult accessMasked = gateway.batchAccess(maskReq).results().get(0);
        BatchItemResult exportMasked = gateway.batchExport(grant.grantId(), maskReq).results().get(0);
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, accessMasked.outcome());
        assertEquals(accessMasked.outcome(), exportMasked.outcome(),
                "普通批量访问与批量导出对同一字段同一持证等级结论必须一致");
        assertEquals(
                accessMasked.decisions().stream().map(FieldDecision::rationale).sorted().toList(),
                exportMasked.decisions().stream().map(FieldDecision::rationale).sorted().toList(),
                "两入口判定依据（路径/动作/原因/所需等级/策略版本）必须一致");
        // 已加密字段在低权限下两入口都维持信封（脱敏不解密），结论与结构口径一致
        @SuppressWarnings("unchecked")
        Map<String, Object> amProfile =
                (Map<String, Object>) accessMasked.view().get("profile");
        @SuppressWarnings("unchecked")
        Map<String, Object> emProfile =
                (Map<String, Object>) exportMasked.view().get("profile");
        assertEquals(amProfile.keySet(), emProfile.keySet(),
                "两入口返回的结构范围必须一致（同一批点名字段不得一个拿到一个丢掉）");
        assertEquals("*******2222", amProfile.get("mobile"));
        assertEquals("*******2222", emProfile.get("mobile"),
                "未加密的点名字段两入口脱敏值一致");

        // raw=true：两入口都必须逐处 DENY
        BatchAccessRequest rawReq = new BatchAccessRequest("ops", Level.PUBLIC, true,
                List.of(new BatchItem("nsel-8", List.of("phone"))));
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ,
                gateway.batchAccess(rawReq).results().get(0).outcome());
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ,
                gateway.batchExport(grant.grantId(), rawReq).results().get(0).outcome());

        // 不存在字段：两入口都必须 FIELD_NOT_FOUND
        BatchAccessRequest missingReq = new BatchAccessRequest("ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-8", List.of("idCard"))));
        assertEquals(ReasonCode.FIELD_NOT_FOUND,
                gateway.batchAccess(missingReq).results().get(0).outcome());
        assertEquals(ReasonCode.FIELD_NOT_FOUND,
                gateway.batchExport(grant.grantId(), missingReq).results().get(0).outcome());
    }

    @Test
    void batch_export_field_out_of_grant_scope_is_denied_even_if_nested() {
        seedComplex("nsel-9");
        // 授权只给 name；点名 phone（即使藏在深层）也必须按条目拒绝
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nsel-9"),
                Set.of("name"), 60_000);
        BatchResponse resp = gateway.batchExport(grant.grantId(), new BatchAccessRequest(
                "ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-9", List.of("phone")))));
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, resp.results().get(0).outcome());
        assertNull(resp.results().get(0).view());

        // 用别名点名同样不得绕过授权范围
        BatchResponse byAlias = gateway.batchExport(grant.grantId(), new BatchAccessRequest(
                "ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-9", List.of("mobile")))));
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, byAlias.results().get(0).outcome());

        // 授权含 phone 时深层字段可正常导出
        ExportGrant grant2 = gateway.issueGrant("ops", Set.of("nsel-9"),
                Set.of("phone"), 60_000);
        BatchResponse ok = gateway.batchExport(grant2.grantId(), new BatchAccessRequest(
                "ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-9", List.of("phone")))));
        assertEquals(ReasonCode.ALLOWED, ok.results().get(0).outcome());
        assertEquals("13800002222", profileOf(ok.results().get(0)).get("mobile"));
    }

    @Test
    void batch_export_missing_field_reported_same_as_access() {
        seedComplex("nsel-10");
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nsel-10"),
                Set.of("idCard", "phone", "name"), 60_000);
        BatchResponse resp = gateway.batchExport(grant.grantId(), new BatchAccessRequest(
                "ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nsel-10", List.of("idCard", "phone")))));
        BatchItemResult r = resp.results().get(0);
        assertEquals(ReasonCode.FIELD_NOT_FOUND, r.outcome());
        assertTrue(r.decisions().stream().anyMatch(
                d -> d.action() == FieldAction.NOT_FOUND && "idCard".equals(d.field())));
        assertEquals("13800002222", profileOf(r).get("mobile"), "取得到的字段照常返回");
    }
}
