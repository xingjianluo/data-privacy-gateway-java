package com.github.xingjianluo.dataprivacygatewayjava.model;

/** 敏感分级，同时作为调用方持证等级；rank 越大要求越高。 */
public enum Level {
    PUBLIC(0),
    INTERNAL(1),
    CONFIDENTIAL(2),
    RESTRICTED(3);

    private final int rank;

    Level(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }

    public boolean covers(Level required) {
        return this.rank >= required.rank;
    }
}
