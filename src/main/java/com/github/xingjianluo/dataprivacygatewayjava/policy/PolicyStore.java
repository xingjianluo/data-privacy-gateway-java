package com.github.xingjianluo.dataprivacygatewayjava.policy;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略内存存储。
 * <p>策略以不可变 {@link AccessPolicy} 快照原子发布（CAS），读者永远读到某一个完整版本，
 * 不会读到半更新的规则集。更新采用乐观版本号：必须基于当前最新版本提交，
 * 旧策略覆盖新策略会被 {@link PolicyConflictException} 明确拒绝。
 */
public class PolicyStore {

    private final AtomicReference<AccessPolicy> snapshot;

    public PolicyStore(AccessPolicy initial) {
        if (initial == null) {
            throw new IllegalArgumentException("initial policy must not be null");
        }
        this.snapshot = new AtomicReference<>(initial);
    }

    public AccessPolicy current() {
        return snapshot.get();
    }

    /**
     * 基于 {@code expectedBaseVersion} 提交新规则集。
     *
     * @throws PolicyConflictException 期望基线版本与当前版本不一致（有人已先行更新）
     */
    public AccessPolicy update(long expectedBaseVersion, List<FieldRule> rules, String updatedAt) {
        if (rules == null || rules.isEmpty()) {
            throw new IllegalArgumentException("policy must contain at least one rule");
        }
        while (true) {
            AccessPolicy base = snapshot.get();
            if (base.version() != expectedBaseVersion) {
                throw new PolicyConflictException(
                        "policy update rejected: expected base version " + expectedBaseVersion
                                + " but current version is " + base.version());
            }
            AccessPolicy next = new AccessPolicy(base.version() + 1, List.copyOf(rules),
                    updatedAt == null ? Instant.now().toString() : updatedAt);
            if (snapshot.compareAndSet(base, next)) {
                return next;
            }
            // CAS 落败说明并发更新已落盘：版本一定已经前进，提交方声明的基线即刻过期。
            // 必须重新与当前版本比对（通常直接抛冲突），绝不允许拿旧基线继续重试推进版本。
        }
    }

    /** 初始策略：缺省规则按字段自身分类控制。 */
    public static AccessPolicy initialPolicy() {
        return new AccessPolicy(1, List.of(FieldRule.defaultRule()), Instant.now().toString());
    }
}
