package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/** 批量整体结果：逐条结论 + 批次级版本戳与截断标记。 */
public final class BatchResponse {
    private final List<BatchItemResult> results;
    private final int requestedCount;
    private final boolean truncated;
    private final long policyVersion;
    private final Integer keyVersion;

    public BatchResponse(List<BatchItemResult> results, int requestedCount, boolean truncated,
                         long policyVersion, Integer keyVersion) {
        this.results = results == null ? List.of() : List.copyOf(results);
        this.requestedCount = requestedCount;
        this.truncated = truncated;
        this.policyVersion = policyVersion;
        this.keyVersion = keyVersion;
    }

    public List<BatchItemResult> results() { return results; }
    public int requestedCount() { return requestedCount; }
    public boolean truncated() { return truncated; }
    public long policyVersion() { return policyVersion; }
    public Integer keyVersion() { return keyVersion; }

    public List<BatchItemResult> getResults() { return results; }
    public int getRequestedCount() { return requestedCount; }
    public boolean isTruncated() { return truncated; }
    public long getPolicyVersion() { return policyVersion; }
    public Integer getKeyVersion() { return keyVersion; }
}
