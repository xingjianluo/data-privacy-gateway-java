package com.github.xingjianluo.dataprivacygatewayjava.policy;

/**
 * 策略版本冲突（旧策略覆盖新策略）。
 */
public class PolicyConflictException extends RuntimeException {
    public PolicyConflictException(String message) {
        super(message);
    }
}
