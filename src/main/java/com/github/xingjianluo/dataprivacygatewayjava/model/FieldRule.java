package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/**
 * 字段策略规则：按字段逻辑名（忽略包装与嵌套深度）匹配。
 * requiredLevel 为读取原始值所需持证等级；低于该等级时按 maskAction 脱敏；
 * 若调用方显式请求原始值(raw=true)而权限不足，则拒绝。
 */
public final class FieldRule {
    private final String field;
    private final Level requiredLevel;
    private final String maskPattern;
    private final List<String> aliases;

    public FieldRule(String field, Level requiredLevel, String maskPattern, List<String> aliases) {
        this.field = field;
        this.requiredLevel = requiredLevel;
        this.maskPattern = maskPattern;
        this.aliases = aliases;
    }

    public String field() { return field; }
    public Level requiredLevel() { return requiredLevel; }
    public String maskPattern() { return maskPattern; }
    public List<String> aliases() { return aliases; }
}
