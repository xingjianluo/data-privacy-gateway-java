package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.BatchService;
import com.github.xingjianluo.dataprivacygatewayjava.service.GrantService;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.AuditStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.GrantStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.RequestDedupStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批量规模/耗时/幂等与授权并发撤销：
 * REJECT 与 TRUNCATE 两种超限约定、超时整批失败不留中间结果、
 * requestId 重试不重复计数、处理期间并发撤销必须拒绝交付。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = {
        "privacy-gateway.batch.max-batch-size=3",
        "privacy-gateway.batch.max-batch-accepted=2",
        "privacy-gateway.batch.max-batch-elapsed-millis=40"
})
class BatchLimitConcurrencyTest {

    private static final Logger LOG = LoggerFactory.getLogger(BatchLimitConcurrencyTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired BatchService batchService;
    @Autowired GrantService grantService;
    @Autowired GatewayProperties properties;
    @Autowired RequestDedupStore dedupStore;
    @Autowired AuditStore auditStore;
    @Autowired KeyStore keyStore;
    @Autowired GrantStore grantStore;

    private List<BatchItemRequest> nItems(int n, String prefix) {
        List<BatchItemRequest> items = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = prefix + "-" + i;
            gateway.ingest("crm", id, Map.of("phone", "1380000" + i), null);
            items.add(new BatchItemRequest(id, null));
        }
        return items;
    }

    @Test
    void reject_mode_oversized_batch_is_refused_entirely() {
        assertEquals(3, properties.getBatch().getMaxBatchSize());
        GatewayException ex = assertThrows(GatewayException.class, () ->
                batchService.accessBatch(new AccessRequest("c", Level.RESTRICTED, "*", false),
                        nItems(4, "blc-reject"), "blc-too-big"));
        assertEquals(ReasonCode.REJECT_BATCH_TOO_LARGE, ex.code());
        LOG.info("[BATCH limit] {} -> {}", "4 条/上限3", ex.code());
    }

    @Test
    void truncate_mode_cuts_batch_and_marks_it() {
        properties.getLimits().setMode(com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode.TRUNCATE);
        try {
            BatchAccessResponse resp = batchService.accessBatch(
                    new AccessRequest("c", Level.RESTRICTED, "*", false),
                    nItems(4, "blc-trunc"), "blc-truncated");
            assertTrue(resp.truncated());
            assertEquals(2, resp.acceptedCount());
            assertEquals(2, resp.results().size());
            assertEquals(ReasonCode.TRUNCATED_BY_LIMIT, resp.reason());
            LOG.info("[BATCH truncate] submitted=4 accepted={} truncated={}",
                    resp.acceptedCount(), resp.truncated());
        } finally {
            properties.getLimits().setMode(com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode.REJECT);
        }
    }

    @Test
    void timeout_fails_whole_batch_without_partial_results() {
        // 40ms 上限：通过受控逐条延迟（每条 30ms）确定性跨越时限
        batchService.setPerItemDelayMillis(30);
        try {
            GatewayException ex = assertThrows(GatewayException.class, () ->
                    batchService.accessBatch(
                            new AccessRequest("slow", Level.RESTRICTED, "*", false),
                            nItems(3, "blc-timeout"), "blc-timeout-1"));
            assertEquals(ReasonCode.REQUEST_TIMEOUT, ex.code());
            // 整批失败留痕，且不返回任何条目结果（无中间明文）
            assertTrue(auditStore.all().stream()
                    .anyMatch(e -> "BATCH_ACCESS_FAIL".equals(e.operation())
                            && e.outcome() == ReasonCode.REQUEST_TIMEOUT));
            LOG.info("[BATCH timeout] {} -> {}", "整批", ex.code());
        } finally {
            batchService.setPerItemDelayMillis(0);
        }
    }

    @Test
    void duplicate_request_id_is_idempotent_and_failure_rolls_back() {
        dedupStore.clear();
        var items = nItems(2, "blc-idem");
        BatchAccessResponse first = batchService.accessBatch(
                new AccessRequest("idem", Level.RESTRICTED, "*", false), items, "same-id");
        assertEquals(2, first.results().size());

        // 同步重试：相同 caller+requestId 被拒绝，不重复处理
        GatewayException dup = assertThrows(GatewayException.class, () ->
                batchService.accessBatch(new AccessRequest("idem", Level.RESTRICTED, "*", false),
                        items, "same-id"));
        assertEquals(ReasonCode.DUPLICATE_REQUEST, dup.code());

        // 整批失败后占位回滚：同 requestId 可以安全重试成功
        try {
            batchService.accessBatch(new AccessRequest("idem", Level.RESTRICTED, "*", false),
                    nItems(4, "blc-idem-fail"), "retryable-id");
            fail("应触发超限");
        } catch (GatewayException expected) {
            assertEquals(ReasonCode.REJECT_BATCH_TOO_LARGE, expected.code());
        }
        BatchAccessResponse retry = batchService.accessBatch(
                new AccessRequest("idem", Level.RESTRICTED, "*", false),
                nItems(2, "blc-idem-retry"), "retryable-id");
        assertEquals(2, retry.results().size());
        LOG.info("[BATCH idempotent] duplicate={} retryAfterFailure=ok", dup.code());
    }

    @Test
    void concurrent_revoke_during_batch_export_rejects_delivery() throws Exception {
        // 准备一批记录并授权全部字段（本类配置单批上限 3 条）
        int n = 3;
        List<BatchItemRequest> items = new ArrayList<>();
        Set<String> ids = new java.util.LinkedHashSet<>();
        for (int i = 0; i < n; i++) {
            String id = "blc-revoke-" + i;
            gateway.ingest("crm", id, Map.of("idCard", "3101011990030" + i), null);
            gateway.encryptFields(id, List.of("idCard"));
            ids.add(id);
            items.add(new BatchItemRequest(id, List.of("idCard")));
        }
        ExportGrant initial = grantService.issue("batch-auditor", ids, Set.of("idCard"), 600_000);

        // 在第一条处理完成后（批量仍在进行）由钩子并发撤销授权；
        // 整批必须在交付前复核处被拒绝且不返回明文。
        batchService.setAfterFirstItemHook(() -> grantStore.revoke(initial.grantId()));
        try {
            GatewayException ex = assertThrows(GatewayException.class, () ->
                    batchService.exportBatch("batch-auditor", Level.PUBLIC, initial.grantId(),
                            items, "blc-concurrent-revoke"));
            assertEquals(ReasonCode.GRANT_REVOKED, ex.code());
        } finally {
            batchService.setAfterFirstItemHook(null);
        }
        boolean audited = auditStore.all().stream()
                .anyMatch(e -> e.outcome() == ReasonCode.GRANT_REVOKED);
        assertTrue(audited);
        LOG.info("[BATCH concurrent-revoke] 处理期间撤销 -> 整批拒绝，已留痕");
    }
}
