package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ConcurrencyUpdateTest {

    private static final Logger LOG = LoggerFactory.getLogger(ConcurrencyUpdateTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired PolicyStore policyStore;
    @Autowired KeyStore keyStore;

    @Test
    void concurrent_policy_publishes_never_half_updated_and_versions_monotonic() throws Exception {
        long before = policyStore.current().version();
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<Long> versions = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    // 每个线程发布一个“phone 需要等级随轮次变化”的完整规则集
                    Level lvl = idx % 2 == 0 ? Level.INTERNAL : Level.CONFIDENTIAL;
                    var p = policyStore.publish(List.of(
                            new FieldRule("phone", lvl, "TAIL4", List.of("mobile"))));
                    versions.add(p.version());
                } catch (Exception ignored) {
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(20, TimeUnit.SECONDS));
        pool.shutdown();
        long after = policyStore.current().version();
        LOG.info("[CONCURRENCY-POLICY] before={} after={} publishedVersions={}",
                before, after, versions.stream().sorted().toList());
        assertEquals(threads, versions.size());
        assertEquals(before + threads, after, "版本必须连续单调递增，旧发布不能覆盖新发布");
        assertEquals(versions.size(), versions.stream().distinct().count(), "版本号不得重复");
        // 历史快照全部可读、不可变，内容与版本对应
        for (long v : versions) {
            assertNotNull(policyStore.byVersion(v));
            assertEquals(1, policyStore.byVersion(v).rules().size());
        }
        // 旧版本不能覆盖新版本
        assertFalse(policyStore.publishAt(after - 1, List.of()));
        assertEquals(after, policyStore.current().version());
    }

    @Test
    void concurrent_key_rotation_keeps_unique_versions_and_history() throws Exception {
        int before = keyStore.currentVersion();
        int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger ok = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    keyStore.rotate(null);
                    ok.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(20, TimeUnit.SECONDS));
        pool.shutdown();
        int after = keyStore.currentVersion();
        LOG.info("[CONCURRENCY-KEY] before={} after={} rotations={} historyVersions={}",
                before, after, ok.get(), keyStore.allVersions().size());
        assertEquals(threads, ok.get());
        assertEquals(before + threads, after);
        // 每个历史版本都可取到密钥（历史密文兼容的前提）
        for (int v = 1; v <= after; v++) {
            assertNotNull(keyStore.byVersion(v), "历史密钥 v" + v + " 必须保留");
        }
    }

    @Test
    void read_during_concurrent_writes_pins_to_one_consistent_snapshot() throws Exception {
        gateway.ingest("crm", "cc-1", Map.of("phone", "13800007777"), null);
        int readers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(readers + 2);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(readers + 2);
        ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();

        // 两个写线程不断发布“phone 降级/升级”的完整策略
        for (int w = 0; w < 2; w++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 20; i++) {
                        Level lvl = i % 2 == 0 ? Level.PUBLIC : Level.CONFIDENTIAL;
                        policyStore.publish(List.of(
                                new FieldRule("phone", lvl, "TAIL4", List.of("mobile"))));
                    }
                } catch (Exception ignored) {
                } finally {
                    done.countDown();
                }
            });
        }
        for (int r = 0; r < readers; r++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AccessResponse resp = gateway.access(
                            new AccessRequest("guest", Level.PUBLIC, "cc-1", false));
                    // 一次响应内：视图结果必须与其所声明策略版本自洽
                    String phone = String.valueOf(resp.view().get("phone"));
                    boolean consistent =
                            (phone.equals("13800007777") || phone.equals("*******7777"))
                            && resp.policyVersion() > 0;
                    outcomes.add(consistent + "@v" + resp.policyVersion() + "@" + phone);
                } catch (GatewayException e) {
                    outcomes.add("EX:" + e.code());
                } catch (InterruptedException ignored) {
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        LOG.info("[CONCURRENCY-RW] outcomes={}", outcomes);
        for (String o : outcomes) {
            assertTrue(o.startsWith("true@"), "每次读取必须与某个确定策略版本自洽，实际：" + o);
        }
        // 无论哪种版本，都不应出现半脱敏或异常拼接
        assertTrue(outcomes.stream().noneMatch(o -> o.contains("EX:")));
    }
}
