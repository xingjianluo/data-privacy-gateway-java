package com.github.xingjianluo.dataprivacygatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 网关可配置上限与留存参数（前缀 {@code privacy.gateway}）。
 */
@ConfigurationProperties(prefix = "privacy.gateway")
public class GatewayProperties {

    private int maxNodesPerRecord = 2000;
    private int maxLeavesPerResponse = 5000;
    private long processingTimeoutMillis = 2000;
    private boolean truncateOversizeArrays = true;
    private int maxArrayLength = 500;
    private long auditRetentionDays = 30;

    public int getMaxNodesPerRecord() {
        return maxNodesPerRecord;
    }

    public void setMaxNodesPerRecord(int maxNodesPerRecord) {
        this.maxNodesPerRecord = maxNodesPerRecord;
    }

    public int getMaxLeavesPerResponse() {
        return maxLeavesPerResponse;
    }

    public void setMaxLeavesPerResponse(int maxLeavesPerResponse) {
        this.maxLeavesPerResponse = maxLeavesPerResponse;
    }

    public long getProcessingTimeoutMillis() {
        return processingTimeoutMillis;
    }

    public void setProcessingTimeoutMillis(long processingTimeoutMillis) {
        this.processingTimeoutMillis = processingTimeoutMillis;
    }

    public boolean isTruncateOversizeArrays() {
        return truncateOversizeArrays;
    }

    public void setTruncateOversizeArrays(boolean truncateOversizeArrays) {
        this.truncateOversizeArrays = truncateOversizeArrays;
    }

    public int getMaxArrayLength() {
        return maxArrayLength;
    }

    public void setMaxArrayLength(int maxArrayLength) {
        this.maxArrayLength = maxArrayLength;
    }

    public long getAuditRetentionDays() {
        return auditRetentionDays;
    }

    public void setAuditRetentionDays(long auditRetentionDays) {
        this.auditRetentionDays = auditRetentionDays;
    }
}
