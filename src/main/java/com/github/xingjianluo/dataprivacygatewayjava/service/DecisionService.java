package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.Policy;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.ResolvedGrant;
import org.springframework.stereotype.Service;

/**
 * 字段级访问判定，结论三选一且原因可区分：
 * <ul>
 *   <li>持证等级覆盖所需等级，或持有的限时授权覆盖该记录+字段：ALLOW（原因 ALLOWED）；</li>
 *   <li>权限不足且普通读取：MASK（脱敏而非报错，原因 MASKED_INSUFFICIENT_CLEARANCE）；</li>
 *   <li>权限不足但显式请求原始值 raw=true：DENY（原因 DENIED_UNAUTHORIZED_RAW_READ）；</li>
 *   <li>明文导出模式下授权/持证均不覆盖：DENY（GRANT_SCOPE_VIOLATION）。</li>
 * </ul>
 * 无策略字段按 PUBLIC 处理：一律 ALLOW。
 * 单条入口与批量导出共用同一判定口径，不会出现一处放行另一处拒绝。
 */
@Service
public class DecisionService {

    public FieldDecision decide(Policy policy, AccessRequest request, String path, String field) {
        return decide(policy, request, path, field, null, null, false);
    }

    public FieldDecision decide(Policy policy, AccessRequest request, String path, String field,
                                ResolvedGrant grant, String recordId) {
        return decide(policy, request, path, field, grant, recordId, false);
    }

    /**
     * @param exportMode 明文导出模式：授权/持证都不放行的点名字段一律判
     *                   DENY({@link ReasonCode#GRANT_SCOPE_VIOLATION})，不做脱敏
     */
    public FieldDecision decide(Policy policy, AccessRequest request, String path, String field,
                                ResolvedGrant grant, String recordId, boolean exportMode) {
        FieldRule rule = findRule(policy, field);
        Level required = rule == null ? Level.PUBLIC : rule.requiredLevel();
        // 授权按策略逻辑名匹配（别名键解析到规则主字段名），与点名字段口径一致
        String logical = rule == null ? field : rule.field();
        boolean granted = grant != null && grant.covers(recordId, logical);
        boolean covered = request.clearance().covers(required) || granted;

        if (covered) {
            return new FieldDecision(path, field, FieldAction.ALLOW, ReasonCode.ALLOWED,
                    request.clearance(), required, policy.version());
        }
        if (exportMode) {
            return new FieldDecision(path, field, FieldAction.DENY,
                    ReasonCode.GRANT_SCOPE_VIOLATION,
                    request.clearance(), required, policy.version());
        }
        // 携带授权读取时，授权只对覆盖字段生效；未覆盖字段回到常规口径，
        // 不按 raw=true 拒绝（授权是加分项，不改变其他字段的既有结论）
        boolean rawEffective = request.rawRequested() && grant == null;
        if (rawEffective) {
            return new FieldDecision(path, field, FieldAction.DENY,
                    ReasonCode.DENIED_UNAUTHORIZED_RAW_READ,
                    request.clearance(), required, policy.version());
        }
        return new FieldDecision(path, field, FieldAction.MASK,
                ReasonCode.MASKED_INSUFFICIENT_CLEARANCE,
                request.clearance(), required, policy.version());
    }

    /** 按字段逻辑名或别名匹配；规则中无该字段返回 null。 */
    public FieldRule findRule(Policy policy, String field) {
        if (policy == null || field == null) {
            return null;
        }
        for (FieldRule rule : policy.rules()) {
            if (field.equals(rule.field())) {
                return rule;
            }
            if (rule.aliases() != null && rule.aliases().contains(field)) {
                return rule;
            }
        }
        return null;
    }
}
