package com.github.xingjianluo.dataprivacygatewayjava.config;

/** 超过处理耗时上限：立即中止，不得残留中间解密结果。 */
public class DeadlineExceededException extends RuntimeException {
    public DeadlineExceededException(String message) {
        super(message);
    }
}
