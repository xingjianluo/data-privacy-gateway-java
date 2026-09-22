package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 接入结果：成功携带归一化记录，失败携带可区分的违例明细。
 *
 * @param accepted   是否接受
 * @param record     归一化记录（成功时）
 * @param violations 拒绝明细：字段路径 -> 拒绝原因
 */
public record IngestionResult(boolean accepted, NormalizedRecord record,
                              Map<String, RejectionReason> violations) {

    public static IngestionResult ok(NormalizedRecord record) {
        return new IngestionResult(true, record, Map.of());
    }

    public static IngestionResult reject(Map<String, RejectionReason> violations) {
        if (violations == null || violations.isEmpty()) {
            throw new IllegalArgumentException("rejection must carry at least one violation");
        }
        return new IngestionResult(false, null, Map.copyOf(violations));
    }

    public List<String> violationSummaries() {
        return violations.entrySet().stream()
                .map(e -> e.getKey() + " -> " + e.getValue() + "(" + e.getValue().description() + ")")
                .toList();
    }
}
