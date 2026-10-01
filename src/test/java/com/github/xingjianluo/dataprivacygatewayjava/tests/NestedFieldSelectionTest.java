package com.github.xingjianluo.dataprivacygatewayjava.tests;

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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 点名字段深度匹配：嵌套子对象 / 数组元素 / value(type-value) 包装 / 别名键。
 * 批量访问与批量明文导出两条入口对同一份数据、同一批字段的结论口径必须一致。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class NestedFieldSelectionTest {

    private static final Logger LOG = LoggerFactory.getLogger(NestedFieldSelectionTest.class);

    @Autowired PrivacyGateway gateway;

    /**
     * 复杂结构记录：phone 同时出现在顶层、别名 mobile、深层对象、数组、
     * 单键 {"value":..} 与双键 {"type":..,"value":..} 包装中；
     * 另含不该被带出来的 name / email 以及无关数组元素。
     */
    private void seedComplex(String id) {
        gateway.ingest("crm", id, Map.of(
                "name", "Alice",
                "city", "Beijing",
                "phone", "13800001111",
                "mobile", "13800002222",
                "email", "alice@example.com",
                "profile", Map.of(
                        "age", 30,
                        "phone", Map.of("value", "13800003333"),
                        "contacts", List.of(
                                Map.of("phone", Map.of("type", "HOME", "value", "13800004444")),
                                Map.of("phone", Map.of("value", "13800005555")),
                                Map.of("mobile", "13800006666"),
                                Map.of("email", "other@example.com")))), null);
    }

    private BatchItemResult accessFields(String caller, Level clearance, String id, String... fields) {
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                caller, clearance, false, List.of(new BatchItem(id, List.of(fields)))));
        return resp.results().get(0);
    }

    /** 期望被深度识别的 6 个 phone/mobile 位点路径（投影后数组下标连续）。 */
    private static final List<String> PHONE_PATHS = List.of(
            "$.phone",
            "$.mobile",
            "$.profile.phone",
            "$.profile.contacts[0].phone",
            "$.profile.contacts[1].phone",
            "$.profile.contacts[2].mobile");

    @Test
    void named_fields_in_nested_array_wrapper_and_alias_are_returned_with_decisions() {
        seedComplex("nf-1");
        BatchItemResult r = accessFields("auditor", Level.RESTRICTED, "nf-1", "phone", "city");
        LOG.info("[NF-CASE=nestedAllow] outcome={} view={}", r.outcome(), r.view());
        LOG.info("[NF-CASE=nestedAllow] decisions={}",
                r.decisions().stream().map(FieldDecision::rationale).toList());

        assertEquals(ReasonCode.ALLOWED, r.outcome());
        assertTrue(r.policyVersion() > 0 && r.keyVersion() > 0, "每条结果必须钉住策略与密钥版本");

        // 顶层与别名
        assertEquals("13800001111", r.view().get("phone"));
        assertEquals("13800002222", r.view().get("mobile"), "别名键必须按逻辑名命中");
        assertEquals("Beijing", r.view().get("city"));
        // 未点名内容绝不多带
        assertFalse(r.view().containsKey("name"));
        assertFalse(r.view().containsKey("email"));

        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) r.view().get("profile");
        assertFalse(profile.containsKey("age"), "未点名的兄弟字段不能带出来");
        @SuppressWarnings("unchecked")
        Map<String, Object> profilePhone = (Map<String, Object>) profile.get("phone");
        assertEquals("13800003333", profilePhone.get("value"), "单键包装深层必须取到");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contacts = (List<Map<String, Object>>) profile.get("contacts");
        assertEquals(3, contacts.size(), "只含命中元素，email 元素必须被裁掉");
        @SuppressWarnings("unchecked")
        Map<String, Object> typed = (Map<String, Object>) contacts.get(0).get("phone");
        assertEquals("HOME", typed.get("type"), "双键包装的 type 骨架要保留");
        assertEquals("13800004444", typed.get("value"));
        @SuppressWarnings("unchecked")
        Map<String, Object> single = (Map<String, Object>) contacts.get(1).get("phone");
        assertEquals("13800005555", single.get("value"));
        assertEquals("13800006666", contacts.get(2).get("mobile"));

        // 每个位点都带自己的判定依据：路径 / 动作 / 原因 / 所需等级 / 策略版本
        for (String path : PHONE_PATHS) {
            FieldDecision d = findDecision(r, path);
            assertNotNull(d, "缺少位点判定依据：" + path);
            assertEquals(FieldAction.ALLOW, d.action());
            assertEquals(ReasonCode.ALLOWED, d.reason());
            assertEquals(Level.CONFIDENTIAL, d.requiredLevel());
            assertEquals(r.policyVersion(), d.policyVersion());
        }
        FieldDecision cityDecision = findDecision(r, "$.city");
        assertNotNull(cityDecision);
        assertEquals(FieldAction.ALLOW, cityDecision.action());
    }

    @Test
    void named_nested_fields_get_masked_decision_per_site_for_low_clearance() {
        seedComplex("nf-2");
        BatchItemResult r = accessFields("guest", Level.PUBLIC, "nf-2", "phone");
        LOG.info("[NF-CASE=nestedMask] outcome={} view={}", r.outcome(), r.view());
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, r.outcome());
        assertEquals("*******1111", r.view().get("phone"));
        assertEquals("*******2222", r.view().get("mobile"));
        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) r.view().get("profile");
        @SuppressWarnings("unchecked")
        Map<String, Object> profilePhone = (Map<String, Object>) profile.get("phone");
        assertEquals("*******3333", profilePhone.get("value"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contacts = (List<Map<String, Object>>) profile.get("contacts");
        @SuppressWarnings("unchecked")
        Map<String, Object> typed = (Map<String, Object>) contacts.get(0).get("phone");
        assertEquals("*******4444", typed.get("value"));
        for (String path : PHONE_PATHS) {
            FieldDecision d = findDecision(r, path);
            assertNotNull(d, "缺少位点判定依据：" + path);
            assertEquals(FieldAction.MASK, d.action());
            assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, d.reason());
            assertEquals(Level.CONFIDENTIAL, d.requiredLevel());
            assertEquals(r.policyVersion(), d.policyVersion());
        }
    }

    @Test
    void missing_named_field_is_reported_not_found_not_allowed_with_empty_view() {
        seedComplex("nf-3");
        // idCard 是受规则管辖但记录中不存在的字段；ghost 是完全无规则的字段
        BatchItemResult r = accessFields("auditor", Level.RESTRICTED, "nf-3", "idCard", "ghost");
        LOG.info("[NF-CASE=missing] outcome={} view={} decisions={}",
                r.outcome(), r.view(), r.decisions().stream().map(FieldDecision::rationale).toList());
        assertEquals(ReasonCode.REJECT_MISSING_FIELD, r.outcome(), "取不到不能报 ALLOW");
        assertTrue(r.view().isEmpty(), "两个点名字段都不存在时视图必须为空");
        FieldDecision idCard = findDecisionByField(r, "idCard");
        assertNotNull(idCard);
        assertEquals(FieldAction.NOT_FOUND, idCard.action());
        assertEquals(ReasonCode.REJECT_MISSING_FIELD, idCard.reason());
        assertEquals(Level.RESTRICTED, idCard.requiredLevel(), "所需等级仍按规则给出");
        assertEquals(r.policyVersion(), idCard.policyVersion());
        FieldDecision ghost = findDecisionByField(r, "ghost");
        assertNotNull(ghost);
        assertEquals(FieldAction.NOT_FOUND, ghost.action());
    }

    @Test
    void partial_missing_field_mixes_allow_and_not_found_in_one_item() {
        seedComplex("nf-4");
        BatchItemResult r = accessFields("auditor", Level.RESTRICTED, "nf-4", "phone", "idCard");
        LOG.info("[NF-CASE=partialMissing] outcome={} decisions={}",
                r.outcome(), r.decisions().stream().map(FieldDecision::rationale).toList());
        assertEquals(ReasonCode.REJECT_MISSING_FIELD, r.outcome());
        assertEquals("13800001111", r.view().get("phone"), "存在的字段照常返回");
        assertNotNull(findDecision(r, "$.phone"));
        assertEquals(FieldAction.ALLOW, findDecision(r, "$.phone").action());
        assertEquals(FieldAction.NOT_FOUND, findDecisionByField(r, "idCard").action(),
                "同一条记录里允许与不存在要逐项分得清");
    }

    @Test
    void one_problem_item_does_not_affect_other_items_in_batch() {
        seedComplex("nf-5a");
        seedComplex("nf-5b");
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest("auditor", Level.RESTRICTED,
                false, List.of(
                new BatchItem("nf-5a", List.of("phone")),
                new BatchItem("nf-5b", List.of("idCard")),
                new BatchItem("nf-missing", List.of("phone")))));
        assertEquals(3, resp.results().size());
        assertEquals(ReasonCode.ALLOWED, resp.results().get(0).outcome());
        assertEquals(ReasonCode.REJECT_MISSING_FIELD, resp.results().get(1).outcome());
        assertEquals(ReasonCode.BAD_REQUEST, resp.results().get(2).outcome());
        // 第一条结论不受后面问题条目影响
        assertEquals("13800001111", resp.results().get(0).view().get("phone"));
    }

    @Test
    void batch_export_reaches_nested_named_fields_with_decisions() {
        seedComplex("nf-6");
        gateway.encryptFields("nf-6", List.of("phone"));
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nf-6"),
                Set.of("phone", "city"), 60_000);
        BatchResponse resp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false,
                        List.of(new BatchItem("nf-6", List.of("phone", "city")))));
        BatchItemResult r = resp.results().get(0);
        LOG.info("[NF-CASE=nestedExport] outcome={} view={}", r.outcome(), r.view());
        assertEquals(ReasonCode.ALLOWED, r.outcome());
        assertEquals("13800001111", r.view().get("phone"), "深层/包装密文同样要被解开为明文");
        assertEquals("13800002222", r.view().get("mobile"));
        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) r.view().get("profile");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contacts = (List<Map<String, Object>>) profile.get("contacts");
        @SuppressWarnings("unchecked")
        Map<String, Object> typed = (Map<String, Object>) contacts.get(0).get("phone");
        assertEquals("13800004444", typed.get("value"));
        assertEquals("13800006666", contacts.get(2).get("mobile"));
        for (String path : PHONE_PATHS) {
            FieldDecision d = findDecision(r, path);
            assertNotNull(d, "导出也必须带每个位点的判定依据：" + path);
            assertEquals(FieldAction.ALLOW, d.action());
            assertEquals(r.policyVersion(), d.policyVersion());
        }
        // 明文不落库
        @SuppressWarnings("unchecked")
        Map<String, Object> stored = gateway.decryptRecord("ops", "nf-6");
        assertEquals("13800001111", stored.get("phone"));
    }

    @Test
    void access_and_export_agree_on_decisions_for_same_named_nested_fields() {
        seedComplex("nf-7");
        gateway.encryptFields("nf-7", List.of("phone"));
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nf-7"),
                Set.of("phone", "city"), 60_000);

        BatchItemResult access = gateway.batchAccess(new BatchAccessRequest(
                "ops", Level.RESTRICTED, false,
                List.of(new BatchItem("nf-7", List.of("phone", "city"))))).results().get(0);
        BatchItemResult export = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false,
                        List.of(new BatchItem("nf-7", List.of("phone", "city"))))).results().get(0);
        LOG.info("[NF-CASE=parity] access={} export={}",
                access.decisions().stream().map(FieldDecision::rationale).toList(),
                export.decisions().stream().map(FieldDecision::rationale).toList());

        assertEquals(ReasonCode.ALLOWED, access.outcome());
        assertEquals(access.outcome(), export.outcome(), "两条入口结论口径必须一致");
        // 位点路径集合一致，逐路径动作一致（导出仅额外把信封解密，不改变字段级判定）
        assertEquals(decisionPathActions(access), decisionPathActions(export));
        // 视图结构（键与层级）一致
        assertEquals(shape(access.view()), shape(export.view()));
        assertEquals(access.policyVersion(), export.policyVersion());
        assertEquals(access.keyVersion(), export.keyVersion());
    }

    @Test
    void named_field_with_null_value_is_present_not_missing() {
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("note", null);
        profile.put("age", 7);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("city", "Beijing");
        data.put("profile", profile);
        gateway.ingest("crm", "nf-10", data, null);
        BatchItemResult r = accessFields("auditor", Level.RESTRICTED, "nf-10", "note");
        LOG.info("[NF-CASE=nullValue] outcome={} view={}", r.outcome(), r.view());
        assertEquals(ReasonCode.ALLOWED, r.outcome(), "字段存在但值为 null 不算缺失");
        @SuppressWarnings("unchecked")
        Map<String, Object> resultProfile = (Map<String, Object>) r.view().get("profile");
        assertTrue(resultProfile.containsKey("note"));
        assertNull(resultProfile.get("note"));
        assertFalse(resultProfile.containsKey("age"), "兄弟字段不能被带出");
        assertNotNull(findDecision(r, "$.profile.note"));
        assertEquals(FieldAction.ALLOW, findDecision(r, "$.profile.note").action());
    }

    @Test
    void raw_request_on_nested_named_field_denies_item_without_view() {
        seedComplex("nf-9");
        // raw=true + PUBLIC：深层/包装/别名的 phone 全部按越权取原文处理，整单拒绝不留视图
        BatchResponse resp = gateway.batchAccess(new BatchAccessRequest(
                "guest", Level.PUBLIC, true,
                List.of(new BatchItem("nf-9", List.of("phone", "city")))));
        BatchItemResult r = resp.results().get(0);
        LOG.info("[NF-CASE=nestedDeny] outcome={} decisions={}",
                r.outcome(), r.decisions().stream().map(FieldDecision::rationale).toList());
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, r.outcome());
        assertNull(r.view(), "越权取原文的条目不能返回任何字段视图，深层命中也不行");
        long denyCount = r.decisions().stream()
                .filter(d -> d.action() == FieldAction.DENY).count();
        assertEquals(PHONE_PATHS.size(), denyCount, "每个 phone 位点都要有 DENY 依据");
    }

    @Test
    void named_field_outside_grant_scope_is_rejected_per_item() {        seedComplex("nf-8");
        ExportGrant grant = gateway.issueGrant("ops", Set.of("nf-8"),
                Set.of("city"), 60_000);
        BatchResponse resp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false,
                        List.of(new BatchItem("nf-8", List.of("phone")))));
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, resp.results().get(0).outcome());
        assertNull(resp.results().get(0).view());
    }

    private static FieldDecision findDecision(BatchItemResult r, String path) {
        return r.decisions().stream().filter(d -> path.equals(d.path())).findFirst().orElse(null);
    }

    private static FieldDecision findDecisionByField(BatchItemResult r, String field) {
        return r.decisions().stream().filter(d -> field.equals(d.field())).findFirst().orElse(null);
    }

    private static Map<String, FieldAction> decisionPathActions(BatchItemResult r) {
        Map<String, FieldAction> map = new LinkedHashMap<>();
        for (FieldDecision d : r.decisions()) {
            map.put(d.path(), d.action());
        }
        return map;
    }

    /** 只保留结构形状（键/层级），值与密文信封统一替换为标记，用于两条入口结构对比。 */
    @SuppressWarnings("unchecked")
    private static Object shape(Object node) {
        if (com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService
                .isEnvelope(node)) {
            return "<v>";
        }
        if (node instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                out.put(String.valueOf(e.getKey()), shape(e.getValue()));
            }
            return out;
        }
        if (node instanceof List<?> list) {
            List<Object> out = new java.util.ArrayList<>();
            for (Object o : list) {
                out.add(shape(o));
            }
            return out;
        }
        return "<v>";
    }
}
