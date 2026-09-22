package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import org.springframework.stereotype.Service;

/**
 * 规模 / 耗时上限守卫。
 * <ul>
 *   <li>REJECT 模式：任何超限直接抛 {@link GatewayException}，调用方不得得到部分处理结果。</li>
 *   <li>TRUNCATE 模式：深度/数组超限可截断（由调用方检查 {@link #mode()} 决定），
 *       字节规模与字符串长度仍拒绝（截断字符串会破坏语义与密文）。</li>
 *   <li>耗时：超过 maxElapsedMillis 以 REQUEST_TIMEOUT 拒绝。</li>
 * </ul>
 */
@Service
public class LimitGuard {

    private final GatewayProperties properties;

    public LimitGuard(GatewayProperties properties) {
        this.properties = properties;
    }

    public void checkDepth(int depth) {
        if (depth > properties.getLimits().getMaxDepth() && mode() == LimitMode.REJECT) {
            throw new GatewayException(ReasonCode.REJECT_DEPTH_EXCEEDED,
                    "嵌套深度 " + depth + " 超过上限 " + properties.getLimits().getMaxDepth());
        }
    }

    /** 数组超限：REJECT 抛异常；TRUNCATE 不抛，由处理方截到 truncateArrayTo。 */
    public void checkArraySize(int size) {
        if (size > properties.getLimits().getMaxArraySize() && mode() == LimitMode.REJECT) {
            throw new GatewayException(ReasonCode.REJECT_ARRAY_TOO_LARGE,
                    "数组长度 " + size + " 超过上限 " + properties.getLimits().getMaxArraySize());
        }
    }

    public void checkStringLength(String value) {
        if (value != null && value.length() > properties.getLimits().getMaxStringLength()) {
            throw new GatewayException(ReasonCode.REJECT_STRING_TOO_LONG,
                    "字符串长度 " + value.length() + " 超过上限 "
                            + properties.getLimits().getMaxStringLength());
        }
    }

    public void checkRecordBytes(int bytes) {
        if (bytes > properties.getLimits().getMaxRecordBytes()) {
            throw new GatewayException(ReasonCode.REJECT_SIZE_EXCEEDED,
                    "记录规模 " + bytes + " 字节超过上限 " + properties.getLimits().getMaxRecordBytes());
        }
    }

    public LimitMode mode() {
        return properties.getLimits().getMode();
    }

    public int truncateArrayTo() {
        return properties.getLimits().getTruncateArrayTo();
    }

    public int maxArraySize() {
        return properties.getLimits().getMaxArraySize();
    }

    public int maxDepth() {
        return properties.getLimits().getMaxDepth();
    }

    public void checkElapsed(long startNanos, ReasonCode context) {
        long elapsedMillis = (System.nanoTime() - startNanos) / 1_000_000L;
        if (elapsedMillis > properties.getLimits().getMaxElapsedMillis()) {
            throw new GatewayException(ReasonCode.REQUEST_TIMEOUT,
                    "处理耗时 " + elapsedMillis + "ms 超过上限 "
                            + properties.getLimits().getMaxElapsedMillis() + "ms（场景：" + context + "）");
        }
    }
}
