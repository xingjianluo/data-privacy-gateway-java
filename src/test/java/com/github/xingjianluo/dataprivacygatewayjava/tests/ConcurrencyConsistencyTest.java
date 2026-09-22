package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessMode;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessResult;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.*;
import com.github.xingjianluo.dataprivacygatewayjava.policy.AccessPolicy;
import com.github.xingjianluo.dataprivacygatewayjava.policy.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.policy.PolicyConflictException;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyRing;
import com.github.xingjianluo.dataprivacygatewayjava.tests.support.TestFixtures;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发一致性：
 * 1) 并发策略更新只能线性前进，旧版本不得覆盖新版本；
 * 2) 并发读取期间，每次结论必须对应某一确定策略版本，且字段依据与结果版本一致；
 * 3) 并发轮换密钥，版本连续不丢，历史密文全部可解。
 */
class ConcurrencyConsistencyTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyConsistencyTest.class);

    @Test
    void concurrentPolicyUpdatesAreLinearAndStaleBaseRejected() throws Exception {
        final var store = TestFixtures.policyStore();
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger conflicts = new AtomicInteger();
        AtomicInteger applied = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            // 所有线程都持有同一个固定基线 v1（在起跑线前确定），CAS 保证恰好一个线性成功
            final long base = store.current().version();
            pool.submit(() -> {
                try {
                    start.await();
                    store.update(base,
                            List.of(new FieldRule("name", DataClassification.FINANCIAL, false),
                                    FieldRule.defaultRule()),
                            Instant.now().toString());
                    applied.incrementAndGet();
                } catch (PolicyConflictException e) {
                    conflicts.incrementAndGet();
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        // 另起一个线程持过期基线，验证"旧覆盖新"被明确拒绝
        pool.submit(() -> {
            try {
                start.await();
                store.update(99L,
                        List.of(new FieldRule("name", DataClassification.PII, false),
                                FieldRule.defaultRule()),
                        Instant.now().toString());
                applied.incrementAndGet();
            } catch (PolicyConflictException e) {
                conflicts.incrementAndGet();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        long finalVersion = store.current().version();
        log.info("[判定依据] applied={}, conflicts={}, finalVersion={}",
                applied.get(), conflicts.get(), finalVersion);
        // 8 个线程基于同一真实基线 v1 竞争 + 1 个持过期基线 v99：
        // 恰好一个线性成功推进到 v2，其余 8 个（含过期基线）全部得到可追溯的冲突拒绝
        assertEquals(1, applied.get(), "v1->v2 只能线性发生一次");
        assertEquals(threads, conflicts.get(), "落败线程与过期基线必须全部被明确拒绝");
        assertEquals(2, finalVersion, "旧策略不得覆盖新策略，版本只能前进到 v2");
    }

    @Test
    void readsUnderConcurrentUpdatesAlwaysMatchOneSnapshot() throws Exception {
        TestFixtures.Gateway fx = new TestFixtures.Gateway();
        IngestionResult ingested = fx.ingestion.ingest(new SourceRecord("crm", "C-CONC",
                Map.of("customerId", "C-CONC", "name", "张三", "idCard", "110101199001011234")));
        assertTrue(ingested.accepted());
        fx.records.put(ingested.record());

        CallerIdentity analyst = new CallerIdentity("analyst",
                Set.of(DataClassification.PUBLIC, DataClassification.INTERNAL, DataClassification.PII));

        int readers = 6;
        int updates = 20;
        ExecutorService pool = Executors.newFixedThreadPool(readers + 2);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> mismatches = new ConcurrentLinkedQueue<>();
        AtomicInteger reads = new AtomicInteger();

        for (int r = 0; r < readers; r++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 50; i++) {
                        AccessResult result = fx.gateway.access(analyst, "C-CONC", AccessMode.NORMAL);
                        reads.incrementAndGet();
                        long pv = result.policyVersion();
                        // 每次读取中，所有字段依据必须与顶层版本完全一致 -> 确定版本快照
                        boolean allSame = result.decisions().stream()
                                .allMatch(d -> d.policyVersion() == pv);
                        if (!allSame) {
                            mismatches.add("mixed policy versions in one read: " + pv);
                        }
                        // idCard（FINANCIAL）analyst 无权读原始值：NORMAL 下必须脱敏，
                        // 任何一次都不得出现明文，证明不存在半更新窗口
                        DataNode.Leaf idCard = findLeaf(result.data(), "idCard");
                        if (idCard != null && "110101199001011234".equals(idCard.value())) {
                            mismatches.add("plaintext leaked under policy v" + pv);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < updates; i++) {
                    AccessPolicy cur = fx.policyStore.current();
                    try {
                        fx.policyStore.update(cur.version(),
                                List.of(new FieldRule("idCard", DataClassification.FINANCIAL, true),
                                        FieldRule.defaultRule()),
                                Instant.now().toString());
                    } catch (PolicyConflictException ignored) {
                        // 并发更新落败是允许的
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < updates; i++) {
                    fx.keyStore.rotate(Instant.now().toString());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));

        log.info("[输入摘要] {} 次读 + 20 次策略更新 + 20 次密钥轮换并发", reads.get());
        log.info("[判定依据] 版本错配/明文泄漏事件数={}, 最终 policyVersion={}, keyVersion={}",
                mismatches.size(), fx.policyStore.current().version(),
                fx.keyStore.current().currentVersion());
        assertTrue(mismatches.isEmpty(), "不得出现混用版本或明文泄漏: " + mismatches);
    }

    @Test
    void concurrentRotationKeepsEveryVersionAndHistoryDecryptable() throws Exception {
        var keyStore = new com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore(
                com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore.initialRing());
        var crypto = new com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService(keyStore);

        // 在轮换前与轮换过程中持续产生密文
        java.util.List<String> ciphertexts = new java.util.concurrent.CopyOnWriteArrayList<>();
        ciphertexts.add(crypto.encrypt("baseline"));

        int rotators = 4;
        ExecutorService pool = Executors.newFixedThreadPool(rotators + 1);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < rotators; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 10; j++) {
                        keyStore.rotate(Instant.now().toString());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        pool.submit(() -> {
            try {
                start.await();
                for (int j = 0; j < 40; j++) {
                    ciphertexts.add(crypto.encrypt("payload-" + j));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));

        KeyRing ring = keyStore.current();
        int expectedVersion = 1 + rotators * 10;
        log.info("[判定依据] 最终 currentVersion={}, 环内版本数={}, 密文样本数={}",
                ring.currentVersion(), ring.versions().size(), ciphertexts.size());
        assertEquals(expectedVersion, ring.currentVersion(), "并发轮换版本必须连续、不丢版本");
        assertEquals(expectedVersion, ring.versions().size(), "全部历史版本必须保留");

        // 所有历史密文都必须能用环内对应版本解密
        for (String c : ciphertexts) {
            String pt = crypto.decrypt(c);
            assertTrue(pt.equals("baseline") || pt.startsWith("payload-"),
                    "历史密文必须全部可解: " + pt);
        }
        log.info("[判定依据] {} 条历史密文全部按自带版本解密成功", ciphertexts.size());
    }

    private static DataNode.Leaf findLeaf(DataNode.Obj root, String key) {
        if (root == null) {
            return null;
        }
        for (Map.Entry<String, DataNode> e : root.fields()) {
            if (e.getKey().equals(key) && e.getValue() instanceof DataNode.Leaf l) {
                return l;
            }
        }
        return null;
    }
}
