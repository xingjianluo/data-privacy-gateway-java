package com.github.xingjianluo.dataprivacygatewayjava.config;

import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** 可配置规模 / 耗时 / 留存上限。 */
@ConfigurationProperties(prefix = "privacy-gateway")
public class GatewayProperties {
    private Limits limits = new Limits();
    private Retention retention = new Retention();
    private Batch batch = new Batch();
    private Grant grant = new Grant();

    public Limits getLimits() { return limits; }
    public void setLimits(Limits limits) { this.limits = limits; }
    public Retention getRetention() { return retention; }
    public void setRetention(Retention retention) { this.retention = retention; }
    public Batch getBatch() { return batch; }
    public void setBatch(Batch batch) { this.batch = batch; }
    public Grant getGrant() { return grant; }
    public void setGrant(Grant grant) { this.grant = grant; }

    public static class Limits {
        private int maxRecordBytes = 16 * 1024;
        private int maxDepth = 8;
        private int maxArraySize = 200;
        private int maxStringLength = 1024;
        private long maxElapsedMillis = 1000;
        private LimitMode mode = LimitMode.REJECT;
        private int truncateArrayTo = 50;
        private int maxAuditEntries = 10_000;

        public int getMaxRecordBytes() { return maxRecordBytes; }
        public void setMaxRecordBytes(int v) { this.maxRecordBytes = v; }
        public int getMaxDepth() { return maxDepth; }
        public void setMaxDepth(int v) { this.maxDepth = v; }
        public int getMaxArraySize() { return maxArraySize; }
        public void setMaxArraySize(int v) { this.maxArraySize = v; }
        public int getMaxStringLength() { return maxStringLength; }
        public void setMaxStringLength(int v) { this.maxStringLength = v; }
        public long getMaxElapsedMillis() { return maxElapsedMillis; }
        public void setMaxElapsedMillis(long v) { this.maxElapsedMillis = v; }
        public LimitMode getMode() { return mode; }
        public void setMode(LimitMode v) { this.mode = v; }
        public int getTruncateArrayTo() { return truncateArrayTo; }
        public void setTruncateArrayTo(int v) { this.truncateArrayTo = v; }
        public int getMaxAuditEntries() { return maxAuditEntries; }
        public void setMaxAuditEntries(int v) { this.maxAuditEntries = v; }
    }

    public static class Retention {
        private long auditTtlMillis = 24 * 3600_000L;

        public long getAuditTtlMillis() { return auditTtlMillis; }
        public void setAuditTtlMillis(long v) { this.auditTtlMillis = v; }
    }

    /** 批量处理上限：单批条数；处理时限复用 limits.maxElapsedMillis。 */
    public static class Batch {
        private int maxItems = 100;

        public int getMaxItems() { return maxItems; }
        public void setMaxItems(int v) { this.maxItems = v; }
    }

    /** 限时授权：默认与最大有效期。 */
    public static class Grant {
        private long defaultTtlMillis = 5 * 60_000L;
        private long maxTtlMillis = 3600_000L;

        public long getDefaultTtlMillis() { return defaultTtlMillis; }
        public void setDefaultTtlMillis(long v) { this.defaultTtlMillis = v; }
        public long getMaxTtlMillis() { return maxTtlMillis; }
        public void setMaxTtlMillis(long v) { this.maxTtlMillis = v; }
    }
}
