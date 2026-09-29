package com.github.xingjianluo.dataprivacygatewayjava.store;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 批量请求幂等去重：caller + requestId 维度记录首次结论摘要（不留明文）。
 * <ul>
 *   <li>TTL 窗口外自动遗忘；</li>
 *   <li>并发的同 requestId 请求靠 {@code putIfAbsent} 只放行一个，
 *       其余作为重试拒绝（DUPLICATE_REQUEST），避免重复计数/状态错乱；</li>
 *   <li>处理失败必须 {@link #release} 回滚占位，使调用方可安全重试；</li>
 *   <li>条目只保存结论码与首事件 id，任何中间明文不进入本存储。</li>
 * </ul>
 */
@Component
public class RequestDedupStore {

    public record DedupEntry(String outcome, String firstAuditEventId, long atMillis) {
    }

    private final ConcurrentMap<String, DedupEntry> seen = new ConcurrentHashMap<>();

    public RequestDedupStore() {
    }

    private static String key(String caller, String requestId) {
        return caller + "|" + requestId;
    }

    /**
     * 尝试占位。首次调用写入并返回 null；若已存在（并发或重试）返回已有条目。
     */
    public DedupEntry tryAcquire(String caller, String requestId, String outcome,
                                 String auditEventId, long nowMillis) {
        DedupEntry incoming = new DedupEntry(outcome, auditEventId, nowMillis);
        DedupEntry existing = seen.putIfAbsent(key(caller, requestId), incoming);
        return existing;
    }

    /** 仅当占位条目仍是自己持有的初始结论时回滚（不覆盖并发已确认条目）。 */
    public void release(String caller, String requestId, String auditEventId) {
        String k = key(caller, requestId);
        seen.computeIfPresent(k, (id, e) ->
                auditEventId != null && auditEventId.equals(e.firstAuditEventId()) ? null : e);
    }

    /** 清理过期条目，返回清理数量。 */
    public int purgeExpired(long ttlMillis, long nowMillis) {
        int removed = 0;
        for (Map.Entry<String, DedupEntry> e : seen.entrySet()) {
            if (nowMillis - e.getValue().atMillis() > ttlMillis) {
                if (seen.remove(e.getKey(), e.getValue())) {
                    removed++;
                }
            }
        }
        return removed;
    }

    /** 测试支持：清空。 */
    public void clear() {
        seen.clear();
    }
}
