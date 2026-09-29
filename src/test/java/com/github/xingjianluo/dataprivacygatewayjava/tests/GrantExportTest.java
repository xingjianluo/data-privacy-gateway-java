package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.BatchService;
import com.github.xingjianluo.dataprivacygatewayjava.service.GrantService;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.AuditStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.GrantStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
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
 * 限时明文授权：发放/范围/跨调用方/过期/撤销/单条与批量口径一致，
 * 以及密钥轮换后的批量历史密文解密。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class GrantExportTest {

    private static final Logger LOG = LoggerFactory.getLogger(GrantExportTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired BatchService batchService;
    @Autowired GrantService grantService;
    @Autowired GrantStore grantStore;
    @Autowired KeyStore keyStore;
    @Autowired AuditStore auditStore;

    private String seedEncryptedRecord(String id) {
        gateway.ingest("crm", id, Map.of(
                "name", "Carol",
                "phone", "13800003333",
                "idCard", "31010119950505002X",
                "email", "carol@example.com"), null);
        // 用当前密钥把敏感字段加密成信封
        gateway.encryptFields(id, List.of("phone", "idCard"));
        return id;
    }

    @Test
    void grant_allows_raw_export_and_decrypts_envelopes() {
        seedEncryptedRecord("ge-1");
        ExportGrant grant = grantService.issue("analyst",
                Set.of("ge-1"), Set.of("idCard", "phone"), 300_000);

        // 低持证等级调用方，凭授权在批量导出中拿到授权字段明文（含信封解密）
        BatchAccessResponse resp = batchService.exportBatch("analyst", Level.PUBLIC,
                grant.grantId(),
                List.of(new BatchItemRequest("ge-1", List.of("idCard", "phone"))),
                "ge-export-1");
        BatchItemResult r = resp.results().get(0);
        assertTrue(r.ok());
        assertEquals(ReasonCode.ALLOWED, r.reason());
        assertEquals("31010119950505002X", r.view().get("idCard"));
        assertEquals("13800003333", r.view().get("phone"));
        // 未点名的字段不出现在结果里
        assertFalse(r.view().containsKey("email"));
        LOG.info("[EXPORT ok] view={}", r.view());
    }

    @Test
    void out_of_scope_field_and_record_are_denied_and_audited() {
        seedEncryptedRecord("ge-2");
        seedEncryptedRecord("ge-3");
        // 只授权 ge-2 的 phone
        ExportGrant grant = grantService.issue("analyst", Set.of("ge-2"), Set.of("phone"), 300_000);

        // 点名字段越出字段范围：该字段拒绝且明文不出现
        BatchAccessResponse resp = batchService.exportBatch("analyst", Level.PUBLIC,
                grant.grantId(),
                List.of(new BatchItemRequest("ge-2", List.of("idCard"))), "ge-scope-1");
        BatchItemResult r = resp.results().get(0);
        assertTrue(r.ok());
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, r.reason());
        assertFalse(r.view().containsKey("idCard"));

        // 记录不在授权范围：整批级拒绝（授权绑定记录范围，不允许访问范围外数据）
        GatewayException ex = assertThrows(GatewayException.class, () ->
                batchService.exportBatch("analyst", Level.PUBLIC, grant.grantId(),
                        List.of(new BatchItemRequest("ge-3", null)), "ge-scope-2"));
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, ex.code());

        // 两类越界都留可追溯记录
        boolean audited = auditStore.all().stream()
                .anyMatch(e -> "BATCH_EXPORT".equals(e.operation())
                        && e.outcome() == ReasonCode.GRANT_SCOPE_VIOLATION);
        assertTrue(audited, "越范围使用授权必须有审计");
        LOG.info("[EXPORT scope] item reason={} batch rejection={}", r.reason(), ex.code());
    }

    @Test
    void wrong_caller_cannot_use_grant() {
        seedEncryptedRecord("ge-4");
        ExportGrant grant = grantService.issue("analyst",
                Set.of("ge-4"), Set.of("idCard"), 300_000);
        GatewayException ex = assertThrows(GatewayException.class, () ->
                batchService.exportBatch("intruder", Level.PUBLIC, grant.grantId(),
                        List.of(new BatchItemRequest("ge-4", null)), "ge-caller"));
        assertEquals(ReasonCode.GRANT_CALLER_MISMATCH, ex.code());
        boolean audited = auditStore.all().stream()
                .anyMatch(e -> "GRANT_USE".equals(e.operation())
                        && e.outcome() == ReasonCode.GRANT_CALLER_MISMATCH);
        assertTrue(audited);
    }

    @Test
    void expired_grant_is_rejected() {
        seedEncryptedRecord("ge-5");
        // ttl 会被钳制到 >=1ms；直接发放后等待自然过期
        ExportGrant grant = grantService.issue("analyst",
                Set.of("ge-5"), Set.of("idCard"), 1);
        await(() -> System.currentTimeMillis() >= grant.expiresAt());
        GatewayException ex = assertThrows(GatewayException.class, () ->
                batchService.exportBatch("analyst", Level.PUBLIC, grant.grantId(),
                        List.of(new BatchItemRequest("ge-5", null)), "ge-expired"));
        assertEquals(ReasonCode.GRANT_EXPIRED, ex.code());
        assertTrue(auditStore.all().stream()
                .anyMatch(e -> e.outcome() == ReasonCode.GRANT_EXPIRED));
    }

    @Test
    void revoked_grant_is_rejected_everywhere() {
        seedEncryptedRecord("ge-6");
        ExportGrant grant = grantService.issue("analyst",
                Set.of("ge-6"), Set.of("idCard"), 300_000);
        assertTrue(grantService.revoke("analyst", grant.grantId()));

        // 批量入口拒绝
        GatewayException batchEx = assertThrows(GatewayException.class, () ->
                batchService.exportBatch("analyst", Level.PUBLIC, grant.grantId(),
                        List.of(new BatchItemRequest("ge-6", null)), "ge-revoke-1"));
        assertEquals(ReasonCode.GRANT_REVOKED, batchEx.code());

        // 单条入口同样拒绝：口径一致
        GatewayException singleEx = assertThrows(GatewayException.class, () ->
                gateway.access(new AccessRequest("analyst", Level.PUBLIC, "ge-6", true,
                        grant.grantId())));
        assertEquals(ReasonCode.GRANT_REVOKED, singleEx.code());
    }

    @Test
    void single_and_batch_have_identical_grant_decision() {
        seedEncryptedRecord("ge-7");
        ExportGrant grant = grantService.issue("analyst",
                Set.of("ge-7"), Set.of("idCard"), 300_000);

        // 同一字段：单条入口凭授权放行
        AccessResponse single = gateway.access(new AccessRequest(
                "analyst", Level.PUBLIC, "ge-7", true, grant.grantId()));
        Object singleValue = single.view().get("idCard");
        assertEquals("31010119950505002X", singleValue);

        // 同一字段：批量导出入口凭授权放行，明文一致
        BatchAccessResponse batch = batchService.exportBatch("analyst", Level.PUBLIC,
                grant.grantId(), List.of(new BatchItemRequest("ge-7", List.of("idCard"))),
                "ge-consistency");
        assertEquals(singleValue, batch.results().get(0).view().get("idCard"));

        // 未持授权时，同一调用方 raw 读取在两个入口都拒绝
        assertThrows(GatewayException.class, () ->
                gateway.access(new AccessRequest("analyst", Level.PUBLIC, "ge-7", true)));
        BatchAccessResponse noGrant = batchService.accessBatch(
                new AccessRequest("analyst", Level.PUBLIC, "*", true),
                List.of(new BatchItemRequest("ge-7", List.of("idCard"))), "ge-consistency-ng");
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ,
                noGrant.results().get(0).reason());
        assertFalse(noGrant.results().get(0).view().containsKey("idCard"));
    }

    @Test
    void batch_export_decrypts_history_ciphertext_after_rotation() {
        seedEncryptedRecord("ge-8");
        int oldKey = keyStore.currentVersion();
        // 轮换后，记录里的信封仍是旧版本
        int newKey = keyStore.rotate(null).version();
        assertTrue(newKey > oldKey);

        ExportGrant grant = grantService.issue("auditor",
                Set.of("ge-8"), Set.of("idCard", "phone"), 300_000);
        BatchAccessResponse resp = batchService.exportBatch("auditor", Level.PUBLIC,
                grant.grantId(), List.of(new BatchItemRequest("ge-8", List.of("idCard", "phone"))),
                "ge-rotate");
        BatchItemResult r = resp.results().get(0);
        assertTrue(r.ok(), "历史密文在轮换后必须能按信封版本解密：" + r.reason());
        assertEquals("31010119950505002X", r.view().get("idCard"));
        assertEquals("13800003333", r.view().get("phone"));
        // 批量固定的是“当前密钥版本戳”，但解密按信封自身 v 取历史密钥
        assertEquals(newKey, r.keyVersion());
        LOG.info("[EXPORT rotate] pinnedKeyV={} 历史信封解密成功", r.keyVersion());
    }

    @Test
    void invalid_grant_requests_are_rejected() {
        assertThrows(GatewayException.class, () ->
                grantService.issue("", Set.of("r"), Set.of("f"), 1000));
        assertThrows(GatewayException.class, () ->
                grantService.issue("c", Set.of(), Set.of("f"), 1000));
        assertThrows(GatewayException.class, () ->
                grantService.issue("c", Set.of("r"), Set.of(), 1000));
        assertThrows(GatewayException.class, () ->
                grantService.revoke("c", "no-such-grant"));
        assertNotNull(grantStore);
    }

    private static void await(java.util.function.BooleanSupplier condition) {
        long deadline = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < deadline && !condition.getAsBoolean()) {
            Thread.onSpinWait();
        }
        assertTrue(condition.getAsBoolean(), "等待条件超时");
    }
}
