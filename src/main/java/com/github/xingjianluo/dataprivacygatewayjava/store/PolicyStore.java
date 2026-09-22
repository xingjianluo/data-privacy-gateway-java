package com.github.xingjianluo.dataprivacygatewayjava.store;

import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.Policy;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 内存策略库：版本化、并发安全。
 * <ul>
 *   <li>每次发布生成全新的不可变 {@link Policy}，通过 {@link AtomicReference} 原子切换，
 *       读线程要么看到完整旧版本，要么看到完整新版本，不存在半更新。</li>
 *   <li>版本号单调递增，旧版本快照保留以供审计/复现；旧版本永远无法覆盖新版本。</li>
 * </ul>
 */
@Component
public class PolicyStore {

    private final AtomicReference<Policy> current = new AtomicReference<>();
    private final AtomicLong versionSeq = new AtomicLong(0);
    private final ConcurrentHashMap<Long, Policy> history = new ConcurrentHashMap<>();

    public PolicyStore() {
    }

    /** 返回当前不可变快照。 */
    public Policy current() {
        return current.get();
    }

    /** 按版本读取快照；不存在返回 null。 */
    public Policy byVersion(long version) {
        return history.get(version);
    }

    /** 原子发布新版本（自动分配单调递增版本号）。 */
    public Policy publish(List<FieldRule> rules) {
        long version = versionSeq.incrementAndGet();
        Policy policy = new Policy(version, List.copyOf(rules));
        history.put(version, policy);
        current.set(policy);
        return policy;
    }

    /**
     * 指定版本发布（并发竞争时低版本不允许覆盖高版本）。
     * @return 发布成功返回 true；版本落后返回 false
     */
    public boolean publishAt(long version, List<FieldRule> rules) {
        synchronized (this) {
            long max = versionSeq.get();
            if (version <= max) {
                return false;
            }
            Policy policy = new Policy(version, List.copyOf(rules));
            history.put(version, policy);
            current.set(policy);
            versionSeq.set(version);
            return true;
        }
    }
}
