package com.github.xingjianluo.dataprivacygatewayjava.store;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.model.AuditEntry;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 内存审计库：
 * <ul>
 *   <li>有界：超过 maxAuditEntries 时整段淘汰最旧条目（条目整体删除，不残留字段）。</li>
 *   <li>留存：purgeExpired 删除 TTL 之外的全部条目。</li>
 *   <li>线程安全：所有读写在同一把锁上，结论与存储顺序一致可复现。</li>
 *   <li>failInjected：测试用失败注入；注入时 append 返回 false 但不抛出。</li>
 * </ul>
 */
@Component
public class AuditStore {

    private final int capacity;
    private final LinkedHashMap<String, AuditEntry> entries = new LinkedHashMap<>(256, 0.75f, true);
    private volatile boolean failInjected;

    public AuditStore(GatewayProperties properties) {
        this.capacity = properties.getLimits().getMaxAuditEntries();
    }

    /** 追加审计；容量超限时淘汰最旧条目。失败注入时返回 false。 */
    public boolean append(AuditEntry entry) {
        if (failInjected) {
            return false;
        }
        synchronized (entries) {
            entries.put(entry.eventId(), entry);
            while (entries.size() > capacity) {
                Iterator<Map.Entry<String, AuditEntry>> it = entries.entrySet().iterator();
                if (!it.hasNext()) {
                    break;
                }
                it.next();
                it.remove();
            }
            return true;
        }
    }

    public List<AuditEntry> query(String recordId) {
        synchronized (entries) {
            List<AuditEntry> result = new ArrayList<>();
            for (AuditEntry e : entries.values()) {
                if (recordId == null || recordId.equals(e.target())) {
                    result.add(e);
                }
            }
            return List.copyOf(result);
        }
    }

    public List<AuditEntry> all() {
        synchronized (entries) {
            return List.copyOf(entries.values());
        }
    }

    public int size() {
        synchronized (entries) {
            return entries.size();
        }
    }

    /** 删除时间戳早于 cutoff 的条目，返回删除数量。删除为整条目移除，不留可识别信息。 */
    public int purgeExpired(long cutoff) {
        synchronized (entries) {
            int removed = 0;
            Iterator<Map.Entry<String, AuditEntry>> it = entries.entrySet().iterator();
            while (it.hasNext()) {
                AuditEntry e = it.next().getValue();
                if (e.timestamp() < cutoff) {
                    it.remove();
                    removed++;
                }
            }
            return removed;
        }
    }

    /** 测试支持：注入审计写入失败。 */
    public void injectFailure(boolean fail) {
        this.failInjected = fail;
    }

    /** 测试支持：清空全部审计数据。 */
    public void clear() {
        synchronized (entries) {
            entries.clear();
        }
    }
}
