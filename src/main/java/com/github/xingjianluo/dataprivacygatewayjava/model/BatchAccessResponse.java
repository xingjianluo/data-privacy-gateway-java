package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/**
 * 批量访问结果：固定一个策略版本与密钥版本，逐条给出结论。
 * 整批级拒绝（超规模/超时/幂等冲突）以异常抛出，不返回本对象。
 */
public final class BatchAccessResponse {
    private final List<BatchItemResult> results;
    private final long policyVersion;
    private final Integer keyVersion;
    private final boolean truncated;
    private final ReasonCode reason;
    private final String requestId;
    private final int acceptedCount;

    public BatchAccessResponse(List<BatchItemResult> results, long policyVersion, Integer keyVersion,
                               boolean truncated, ReasonCode reason, String requestId, int acceptedCount) {
        this.results = results;
        this.policyVersion = policyVersion;
        this.keyVersion = keyVersion;
        this.truncated = truncated;
        this.reason = reason;
        this.requestId = requestId;
        this.acceptedCount = acceptedCount;
    }

    public List<BatchItemResult> results() { return results; }
    public long policyVersion() { return policyVersion; }
    public Integer keyVersion() { return keyVersion; }
    public boolean truncated() { return truncated; }
    public ReasonCode reason() { return reason; }
    public String requestId() { return requestId; }
    public int acceptedCount() { return acceptedCount; }

    // --- Jackson 友好访问器 ---
    public List<BatchItemResult> getResults() { return results; }
    public long getPolicyVersion() { return policyVersion; }
    public Integer getKeyVersion() { return keyVersion; }
    public boolean isTruncated() { return truncated; }
    public ReasonCode getReason() { return reason; }
    public String getRequestId() { return requestId; }
    public int getAcceptedCount() { return acceptedCount; }
}
