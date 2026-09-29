package com.github.xingjianluo.dataprivacygatewayjava.store;

import com.github.xingjianluo.dataprivacygatewayjava.model.ExportGrant;
import com.github.xingjianluo.dataprivacygatewayjava.model.GrantStatus;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 内存限时授权库：发放/查询/撤销均为原子操作。
 * <ul>
 *   <li>{@link ExportGrant} 本身不可变，读取返回的快照引用在一次批量处理期间始终确定，
 *       撤销只会替换映射，不会半新半旧；</li>
 *   <li>撤销用 {@link ConcurrentHashMap#compute} 原子完成，已撤销保持已撤销；</li>
 *   <li>授权 id 唯一，重复发放同一 id 被拒绝。</li>
 * </ul>
 */
@Component
public class GrantStore {

    private final ConcurrentMap<String, ExportGrant> grants = new ConcurrentHashMap<>();

    public GrantStore() {
    }

    /**
     * 存放新授权。
     * @return true 存放成功；id 已存在返回 false
     */
    public boolean put(ExportGrant grant) {
        return grants.putIfAbsent(grant.grantId(), grant) == null;
    }

    /** 按 id 取授权快照；不存在返回 null。 */
    public ExportGrant get(String grantId) {
        return grantId == null ? null : grants.get(grantId);
    }

    /**
     * 原子撤销；已撤销保持已撤销。
     * @return 撤销成功（存在且原状态为 ACTIVE）返回 true；不存在或本已撤销返回 false
     */
    public boolean revoke(String grantId) {
        boolean[] changed = {false};
        grants.computeIfPresent(grantId, (id, g) -> {
            if (g.status() == GrantStatus.ACTIVE) {
                changed[0] = true;
                return g.withStatus(GrantStatus.REVOKED);
            }
            return g;
        });
        return changed[0];
    }
}
