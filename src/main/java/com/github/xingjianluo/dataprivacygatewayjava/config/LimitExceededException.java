package com.github.xingjianluo.dataprivacygatewayjava.config;

/** 超过规模上限（按既定策略拒绝或截断）。 */
public class LimitExceededException extends RuntimeException {
    public LimitExceededException(String message) {
        super(message);
    }
}
