package com.github.xingjianluo.dataprivacygatewayjava.access;

/**
 * 访问模式：NORMAL 低权限脱敏；RAW 越权读取原始值（必须被拒绝）。
 */
public enum AccessMode {
    NORMAL,
    RAW
}
