package com.github.xingjianluo.dataprivacygatewayjava.policy;

import java.util.List;

/**
 * 某一版本的访问策略快照，不可变。
 */
public record AccessPolicy(long version, List<FieldRule> rules, String updatedAt) {

    public AccessPolicy {
        rules = List.copyOf(rules);
    }
}
