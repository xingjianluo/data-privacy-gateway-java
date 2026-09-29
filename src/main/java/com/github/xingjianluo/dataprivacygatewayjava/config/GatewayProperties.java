package com.github.xingjianluo.dataprivacygatewayjava.config;

import com.github.xingjianluo.dataprivacygatewayjava.model.LimitMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** 可配置规模 / 耗时 / 留存上限。 */
@ConfigurationProperties(prefix = "privacy-gateway")
public class GatewayProperties {
    private Limits limits = new Limits();
    private Retention retention = new Retention();
    private Batch batch = new Batch();

    public Limits getLimits() { return limits; }
    public void setLimits(Limits limits) { this.limits = limits; }
    public Retention getRetention() { return retention; }
    public void setRetention(Retention retention) { this.retention = retention; }
    public Batch getBatch() { return batch; }
    public void setBatch(Batch batch) { this.batch = batch; }

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

    /** 批量访问规模 / 耗时上限；超限按 mode 拒绝或截断条数。 */
    public static class Batch {
        /** 单批最大条数；REJECT 模式超限整批拒绝，TRUNCATE 模式截断到 maxBatchAccepted。 */
        private int maxBatchSize = 100;
        /** TRUNCATE 模式下实际处理的条数。 */
        private int maxBatchAccepted = 50;
        /** 整批处理耗时上限（毫秒），超时整批失败、不返回中间结果。 */
        private long maxBatchElapsedMillis = 3000;
        /** 授权有效期上限（毫秒），申请 TTL 超过此值按上限发放。 */
        private long maxGrantTtlMillis = 15 * 60_000L;
        /** 幂等去重记忆窗口（毫秒），窗口内相同 caller+requestId 视为重试。 */
        private long idempotencyTtlMillis = 10 * 60_000L;

        public int getMaxBatchSize() { return maxBatchSize; }
        public void setMaxBatchSize(int v) { this.maxBatchSize = v; }
        public int getMaxBatchAccepted() { return maxBatchAccepted; }
        public void setMaxBatchAccepted(int v) { this.maxBatchAccepted = v; }
        public long getMaxBatchElapsedMillis() { return maxBatchElapsedMillis; }
        public void setMaxBatchElapsedMillis(long v) { this.maxBatchElapsedMillis = v; }
        public long getMaxGrantTtlMillis() { return maxGrantTtlMillis; }
        public void setMaxGrantTtlMillis(long v) { this.maxGrantTtlMillis = v; }
        public long getIdempotencyTtlMillis() { return idempotencyTtlMillis; }
        public void setIdempotencyTtlMillis(long v) { this.idempotencyTtlMillis = v; }
    }
}
