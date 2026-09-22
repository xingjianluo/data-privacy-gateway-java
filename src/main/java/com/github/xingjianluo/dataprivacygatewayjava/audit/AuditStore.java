package com.github.xingjianluo.dataprivacygatewayjava.audit;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 审计内存存储。
 * <ul>
 *   <li>{@link #record(AuditEvent)} 永不向调用方抛出：写入失败仅计数并返回 false，
 *       由调用方保证主流程结论不变。</li>
 *   <li>{@link #purgeExpired(Instant)} 物理删除过期记录（先从索引摘除，使其不再可达），
 *       清除后存储中不残留任何可识别信息。</li>
 * </ul>
 */
public class AuditStore {

    private final long retentionDays;
    private final Map<String, AuditEvent> events = new ConcurrentHashMap<>();
    private final AtomicBoolean failNext = new AtomicBoolean(false);
    private final AtomicInteger failedWrites = new AtomicInteger(0);
    private volatile Clock clock = Clock.systemUTC();

    public AuditStore(long retentionDays) {
        this.retentionDays = retentionDays;
    }

    /** 测试用：注入时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    public long retentionDays() {
        return retentionDays;
    }

    public boolean record(AuditEvent event) {
        try {
            if (failNext.compareAndSet(true, false)) {
                throw new IllegalStateException("simulated audit write failure");
            }
            if (event == null || event.eventId() == null) {
                throw new IllegalArgumentException("audit event incomplete");
            }
            events.put(event.eventId(), event);
            return true;
        } catch (RuntimeException e) {
            failedWrites.incrementAndGet();
            return false;
        }
    }

    public void failNextWrite() {
        failNext.set(true);
    }

    public int failedWriteCount() {
        return failedWrites.get();
    }

    public List<AuditEvent> findByRecord(String recordId) {
        return events.values().stream()
                .filter(e -> e.recordId() != null && e.recordId().equals(recordId))
                .sorted((a, b) -> a.timestamp().compareTo(b.timestamp()))
                .toList();
    }

    public List<AuditEvent> all() {
        return List.copyOf(events.values());
    }

    /**
     * 清除已过期记录，返回清除条数。删除即从 {@link #events} 摘除引用，
     * 不做任何字段副本留存，确保可识别信息不残留。
     */
    public int purgeExpired(Instant now) {
        Instant cutoff = now.minusSeconds(retentionDays * 24 * 60 * 60);
        int[] removed = {0};
        events.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().timestamp().isBefore(cutoff);
            if (expired) {
                removed[0]++;
            }
            return expired;
        });
        return removed[0];
    }

    public int size() {
        return events.size();
    }
}
