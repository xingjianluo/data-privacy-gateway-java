package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldAction;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.Policy;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import org.springframework.stereotype.Service;

/**
 * 字段级访问判定，结论三选一且原因可区分：
 * <ul>
 *   <li>持证等级覆盖所需等级：ALLOW（原因 ALLOWED）；</li>
 *   <li>权限不足且普通读取：MASK（脱敏而非报错，原因 MASKED_INSUFFICIENT_CLEARANCE）；</li>
 *   <li>权限不足但显式请求原始值 raw=true：DENY（原因 DENIED_UNAUTHORIZED_RAW_READ）。</li>
 * </ul>
 * 无策略字段按 PUBLIC 处理：一律 ALLOW。
 */
@Service
public class DecisionService {

    public FieldDecision decide(Policy policy, AccessRequest request, String path, String field) {
        FieldRule rule = findRule(policy, field);
        Level required = rule == null ? Level.PUBLIC : rule.requiredLevel();
        boolean covered = request.clearance().covers(required);

        if (covered) {
            return new FieldDecision(path, field, FieldAction.ALLOW, ReasonCode.ALLOWED,
                    request.clearance(), required, policy.version());
        }
        if (request.rawRequested()) {
            return new FieldDecision(path, field, FieldAction.DENY,
                    ReasonCode.DENIED_UNAUTHORIZED_RAW_READ,
                    request.clearance(), required, policy.version());
        }
        return new FieldDecision(path, field, FieldAction.MASK,
                ReasonCode.MASKED_INSUFFICIENT_CLEARANCE,
                request.clearance(), required, policy.version());
    }

    /**
     * 点名的逻辑字段在记录任何层级/包装/别名下都不存在或取不到：
     * 显式给出 NOT_FOUND 依据，绝不允许用「空结果 + ALLOW」含糊带过。
     */
    public FieldDecision notFound(Policy policy, AccessRequest request, String field) {
        return new FieldDecision("$", field, FieldAction.NOT_FOUND, ReasonCode.FIELD_NOT_FOUND,
                request.clearance(), Level.PUBLIC, policy.version());
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
