package com.github.xingjianluo.dataprivacygatewayjava.tests.support;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessGateway;
import com.github.xingjianluo.dataprivacygatewayjava.access.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditService;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditStore;
import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.FieldKind;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.FieldSpec;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.IngestionService;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceProfile;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskStrategy;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskingService;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;
import com.github.xingjianluo.dataprivacygatewayjava.policy.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.policy.PolicyStore;

import java.util.List;
import java.util.Map;

/**
 * 测试夹具：手工装配一套最小网关，避免依赖 Spring 上下文。
 */
public final class TestFixtures {

    private TestFixtures() {
    }

    public static GatewayProperties properties() {
        GatewayProperties p = new GatewayProperties();
        p.setMaxNodesPerRecord(200);
        p.setMaxLeavesPerResponse(500);
        p.setProcessingTimeoutMillis(2000);
        p.setMaxArrayLength(50);
        p.setAuditRetentionDays(30);
        return p;
    }

    public static SourceProfile crmProfile() {
        return new SourceProfile("crm", "customerId", Map.of(
                "customerId", new FieldSpec("customerId", DataClassification.INTERNAL, true, FieldKind.SCALAR),
                "name", new FieldSpec("name", DataClassification.PII, true, FieldKind.SCALAR),
                "idCard", new FieldSpec("idCard", DataClassification.FINANCIAL, true,
                        FieldKind.SCALAR, true),
                "contacts", new FieldSpec("contacts", DataClassification.PII, false, FieldKind.ARRAY),
                "idCards", new FieldSpec("idCards", DataClassification.FINANCIAL, false,
                        FieldKind.ARRAY, true)
        ), false, DataClassification.INTERNAL);
    }

    public static IngestionService ingestionService(KeyStore keyStore, GatewayProperties p) {
        CryptoService crypto = new CryptoService(keyStore);
        return new IngestionService(Map.of("crm", crmProfile()),
                p.getMaxNodesPerRecord(), List.of(), crypto,
                p.getMaxArrayLength(), p.isTruncateOversizeArrays());
    }

    public static PolicyStore policyStore() {
        return new PolicyStore(new com.github.xingjianluo.dataprivacygatewayjava.policy.AccessPolicy(
                1,
                List.of(new FieldRule("idCard", DataClassification.FINANCIAL, true),
                        FieldRule.defaultRule()),
                java.time.Instant.now().toString()));
    }

    public static class Gateway {
        public final KeyStore keyStore;
        public final CryptoService crypto;
        public final PolicyStore policyStore;
        public final MaskingService masking;
        public final RecordStore records;
        public final AuditStore auditStore;
        public final AuditService audit;
        public final IngestionService ingestion;
        public final AccessGateway gateway;
        public final GatewayProperties properties;

        public Gateway() {
            this(properties());
        }

        public Gateway(GatewayProperties p) {
            this.properties = p;
            this.keyStore = new KeyStore(KeyStore.initialRing());
            this.crypto = new CryptoService(keyStore);
            this.policyStore = policyStore();
            this.masking = new MaskingService(MaskStrategy.PARTIAL);
            this.records = new RecordStore();
            this.auditStore = new AuditStore(p.getAuditRetentionDays());
            this.audit = new AuditService(auditStore, p.getAuditRetentionDays());
            this.ingestion = new IngestionService(Map.of("crm", crmProfile()),
                    p.getMaxNodesPerRecord(), List.of(), crypto,
                    p.getMaxArrayLength(), p.isTruncateOversizeArrays());
            this.gateway = new AccessGateway(records, policyStore, crypto, masking, audit, p);
        }
    }
}
