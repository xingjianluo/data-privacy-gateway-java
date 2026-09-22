package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/** 不可变策略版本快照。 */
public final class Policy {
    private final long version;
    private final List<FieldRule> rules;

    public Policy(long version, List<FieldRule> rules) {
        this.version = version;
        this.rules = rules;
    }

    public long version() { return version; }
    public List<FieldRule> rules() { return rules; }

    // --- Jackson 友好访问器（与方法式访问器并存）---
    public long getVersion() { return version; }
    public List<FieldRule> getRules() { return rules; }
}
