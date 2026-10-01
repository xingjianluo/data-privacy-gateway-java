package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItem;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.AuditStore;
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
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ExportGrantTest {

    private static final Logger LOG = LoggerFactory.getLogger(ExportGrantTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired AuditStore auditStore;
    @Autowired KeyStore keyStore;

    private void seedEncrypted() {
        gateway.ingest("crm", "ex-1", Map.of(
                "name", "Alice", "phone", "13800001111", "city", "Beijing"), null);
        gateway.ingest("crm", "ex-2", Map.of(
                "name", "Bob", "phone", "13900002222", "city", "Shanghai"), null);
        gateway.encryptFields("ex-1", List.of("phone"));
        gateway.encryptFields("ex-2", List.of("phone"));
    }

    private ExportGrant grantFor(String caller, String... recordIds) {
        return gateway.issueGrant(caller, Set.of(recordIds), Set.of("name", "phone"), 60_000);
    }

    @Test
    void export_happy_path_returns_plaintext_within_scope() {
        seedEncrypted();
        ExportGrant grant = grantFor("ops", "ex-1");
        BatchResponse resp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false,
                        List.of(new BatchItem("ex-1", List.of("name", "phone")))));
        BatchItemResult r = resp.results().get(0);
        LOG.info("[GRANT-CASE=happy] outcome={} view={}", r.outcome(), r.view());
        assertEquals(ReasonCode.ALLOWED, r.outcome());
        assertEquals("13800001111", r.view().get("phone"), "密文信封应被解开为明文");
        assertEquals("Alice", r.view().get("name"));
        // 明文不落库：记录库中仍是密文信封
        Map<String, Object> stored = gateway.decryptRecord("ops", "ex-1");
        assertEquals("13800001111", stored.get("phone"));
    }

    @Test
    void export_out_of_scope_record_is_denied_per_item_with_audit() {
        seedEncrypted();
        ExportGrant grant = grantFor("ops", "ex-1");
        BatchResponse resp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false, List.of(
                        new BatchItem("ex-1", List.of("name")),
                        new BatchItem("ex-2", List.of("name")))));
        LOG.info("[GRANT-CASE=recordScope] results={}",
                resp.results().stream().map(r -> r.recordId() + "->" + r.outcome()).toList());
        assertEquals(ReasonCode.ALLOWED, resp.results().get(0).outcome());
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, resp.results().get(1).outcome());
        assertNull(resp.results().get(1).view());
        boolean audited = auditStore.query("ex-2").stream()
                .anyMatch(e -> e.outcome() == ReasonCode.GRANT_SCOPE_VIOLATION);
        assertTrue(audited, "越范围访问必须留审计");
    }

    @Test
    void export_out_of_scope_field_is_denied() {
        seedEncrypted();
        ExportGrant grant = gateway.issueGrant("ops", Set.of("ex-1"), Set.of("name"), 60_000);
        BatchResponse resp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false,
                        List.of(new BatchItem("ex-1", List.of("phone")))));
        LOG.info("[GRANT-CASE=fieldScope] outcome={}", resp.results().get(0).outcome());
        assertEquals(ReasonCode.GRANT_SCOPE_VIOLATION, resp.results().get(0).outcome());
    }

    @Test
    void expired_grant_is_rejected_with_audit() throws Exception {
        seedEncrypted();
        ExportGrant grant = gateway.issueGrant("ops", Set.of("ex-1"), Set.of("name"), 1);
        Thread.sleep(30);
        GatewayException ex = assertThrows(GatewayException.class, () ->
                gateway.batchExport(grant.grantId(),
                        new BatchAccessRequest("ops", Level.RESTRICTED, false,
                                List.of(new BatchItem("ex-1", List.of("name"))))));
        LOG.warn("[GRANT-CASE=expired] code={} message={}", ex.code(), ex.getMessage());
        assertEquals(ReasonCode.GRANT_EXPIRED, ex.code());
        boolean audited = auditStore.all().stream()
                .anyMatch(e -> e.outcome() == ReasonCode.GRANT_EXPIRED);
        assertTrue(audited, "过期授权使用必须留审计");
    }

    @Test
    void cross_caller_use_is_rejected_with_audit() {
        seedEncrypted();
        ExportGrant grant = grantFor("ops", "ex-1");
        GatewayException ex = assertThrows(GatewayException.class, () ->
                gateway.batchExport(grant.grantId(),
                        new BatchAccessRequest("mallory", Level.RESTRICTED, false,
                                List.of(new BatchItem("ex-1", List.of("name"))))));
        LOG.warn("[GRANT-CASE=crossCaller] code={} message={}", ex.code(), ex.getMessage());
        assertEquals(ReasonCode.GRANT_CALLER_MISMATCH, ex.code());
        boolean audited = auditStore.all().stream()
                .anyMatch(e -> e.outcome() == ReasonCode.GRANT_CALLER_MISMATCH
                        && "mallory".equals(e.caller()));
        assertTrue(audited, "跨调用方使用必须留审计");
    }

    @Test
    void revoked_grant_is_rejected() {
        seedEncrypted();
        ExportGrant grant = grantFor("ops", "ex-1");
        assertTrue(gateway.revokeGrant(grant.grantId()));
        GatewayException ex = assertThrows(GatewayException.class, () ->
                gateway.batchExport(grant.grantId(),
                        new BatchAccessRequest("ops", Level.RESTRICTED, false,
                                List.of(new BatchItem("ex-1", List.of("name"))))));
        LOG.warn("[GRANT-CASE=revoked] code={} message={}", ex.code(), ex.getMessage());
        assertEquals(ReasonCode.GRANT_NOT_FOUND, ex.code());
    }

    @Test
    void grant_does_not_widen_field_level_decisions() {
        seedEncrypted();
        ExportGrant grant = grantFor("ops", "ex-1");
        // 单条入口：PUBLIC + raw 取 phone -> DENY
        GatewayException single = assertThrows(GatewayException.class, () ->
                gateway.access(new AccessRequest("ops", Level.PUBLIC, "ex-1", true)));
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, single.code());
        // 批量导出入口：显式 raw=true + 低持证等级，同样必须得到字段级拒绝
        BatchResponse rawResp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.PUBLIC, true,
                        List.of(new BatchItem("ex-1", List.of("phone")))));
        LOG.info("[GRANT-CASE=consistentRaw] single={} batchItem={}",
                single.code(), rawResp.results().get(0).outcome());
        assertEquals(ReasonCode.DENIED_UNAUTHORIZED_RAW_READ, rawResp.results().get(0).outcome(),
                "授权只收紧不放宽：raw=true 时两个入口都必须字段级拒绝");
        assertNull(rawResp.results().get(0).view());
        // 普通读取（raw=false）+ 低持证等级：两个入口都必须逐字段脱敏（口径一致），
        // 授权不会把权限放宽成可取明文
        BatchResponse maskResp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.PUBLIC, false,
                        List.of(new BatchItem("ex-1", List.of("phone")))));
        BatchResponse accessMask = gateway.batchAccess(
                new BatchAccessRequest("ops", Level.PUBLIC, false,
                        List.of(new BatchItem("ex-1", List.of("phone")))));
        LOG.info("[GRANT-CASE=consistentMask] export={} access={}",
                maskResp.results().get(0).outcome(), accessMask.results().get(0).outcome());
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE,
                maskResp.results().get(0).outcome());
        assertEquals(accessMask.results().get(0).outcome(), maskResp.results().get(0).outcome(),
                "同一字段同一持证等级，普通批量访问与批量导出结论必须一致");
        // 已加密的 phone 信封在低权限下不被解开
        Object exportedPhone = maskResp.results().get(0).view().get("phone");
        assertTrue(AesGcmCryptoService.isEnvelope(exportedPhone),
                "授权不放宽：低权限导出不得解开密文信封");
    }

    @Test
    void batch_export_decrypts_historical_ciphertext_after_rotation() {
        seedEncrypted();
        int oldVersion = keyStore.currentVersion();
        var km = keyStore.rotate(null);
        LOG.info("[GRANT-CASE=rotation] oldV={} newV={}", oldVersion, km.version());
        ExportGrant grant = grantFor("ops", "ex-1", "ex-2");
        BatchResponse resp = gateway.batchExport(grant.grantId(),
                new BatchAccessRequest("ops", Level.RESTRICTED, false, List.of(
                        new BatchItem("ex-1", List.of("phone")),
                        new BatchItem("ex-2", List.of("phone")))));
        LOG.info("[GRANT-CASE=rotation] results={}",
                resp.results().stream().map(r -> r.recordId() + "->" + r.outcome()
                        + " view=" + r.view() + " keyV=" + r.keyVersion()).toList());
        assertEquals("13800001111", resp.results().get(0).view().get("phone"),
                "轮换后历史密文（v" + oldVersion + "）必须仍能正确解密");
        assertEquals("13900002222", resp.results().get(1).view().get("phone"));
        // 每条结果都钉在批次开始时的密钥版本上
        assertTrue(resp.results().stream().allMatch(r -> r.keyVersion() == km.version()));
    }

    @Test
    void concurrent_revocation_each_batch_is_fully_valid_or_fully_rejected() throws Exception {
        seedEncrypted();
        ExportGrant grant = grantFor("ops", "ex-1");
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 20; j++) {
                        try {
                            BatchResponse resp = gateway.batchExport(grant.grantId(),
                                    new BatchAccessRequest("ops", Level.RESTRICTED, false,
                                            List.of(new BatchItem("ex-1", List.of("name", "phone")))));
                            boolean allOk = resp.results().size() == 1
                                    && resp.results().get(0).outcome() == ReasonCode.ALLOWED
                                    && "13800001111".equals(resp.results().get(0).view().get("phone"));
                            outcomes.add(allOk ? "FULL_OK" : "BROKEN_PARTIAL");
                        } catch (GatewayException e) {
                            outcomes.add(e.code() == ReasonCode.GRANT_NOT_FOUND
                                    ? "CLEAN_REJECT" : "BROKEN_" + e.code());
                        }
                    }
                } catch (InterruptedException ignored) {
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        // 中途撤销授权
        Thread.sleep(10);
        gateway.revokeGrant(grant.grantId());
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        LOG.info("[GRANT-CASE=concurrentRevoke] outcomes={}",
                outcomes.stream().collect(java.util.stream.Collectors.groupingBy(o -> o,
                        java.util.stream.Collectors.counting())));
        assertFalse(outcomes.isEmpty());
        assertTrue(outcomes.stream().allMatch(o -> o.equals("FULL_OK") || o.equals("CLEAN_REJECT")),
                "并发撤销下每批要么完整成功、要么干净拒绝，不得出现半新半旧：" + outcomes);
    }
}
