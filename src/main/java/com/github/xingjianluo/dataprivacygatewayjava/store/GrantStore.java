package com.github.xingjianluo.dataprivacygatewayjava.store;

import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存授权库：
 * <ul>
 *   <li>授权对象不可变；撤销 = 原子移除，读取方要么看到完整授权、要么看不到，不存在半撤销。</li>
 *   <li>过期不主动删除，由校验方按 expiresAt 判定（过期即失效），并定期清理。</li>
 * </ul>
 */
@Component
public class GrantStore {

    private final Map<String, ExportGrant> grants = new ConcurrentHashMap<>();

    public void put(ExportGrant grant) {
        grants.put(grant.grantId(), grant);
    }

    /** 按 id 取授权快照；不存在（含已撤销）返回 null。 */
    public ExportGrant get(String grantId) {
        return grantId == null ? null : grants.get(grantId);
    }

    /** 撤销授权；返回是否真的移除了一条。 */
    public boolean revoke(String grantId) {
        return grantId != null && grants.remove(grantId) != null;
    }

    /** 清理已过期授权，返回清理数量。 */
    public int purgeExpired(long nowMillis) {
        int removed = 0;
        for (Map.Entry<String, ExportGrant> e : grants.entrySet()) {
            if (e.getValue().expiredAt(nowMillis) && grants.remove(e.getKey(), e.getValue())) {
                removed++;
            }
        }
        return removed;
    }

    public int size() {
        return grants.size();
    }

    /** 测试支持：清空全部授权。 */
    public void clear() {
        grants.clear();
    }
}
