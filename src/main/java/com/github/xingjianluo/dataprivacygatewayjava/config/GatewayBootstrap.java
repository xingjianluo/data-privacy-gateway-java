package com.github.xingjianluo.dataprivacygatewayjava.config;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessGateway;
import com.github.xingjianluo.dataprivacygatewayjava.access.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditService;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditStore;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.CsvSourceAdapter;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.FieldKind;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.FieldSpec;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.IngestionService;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceProfile;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskStrategy;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskingService;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;
import com.github.xingjianluo.dataprivacygatewayjava.policy.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.policy.PolicyStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

/**
 * Spring 装配：默认策略、初始密钥环、演示来源画像（含落库加密字段）。
 */
@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
public class GatewayBootstrap {

    @Bean
    public PolicyStore policyStore() {
        // 显式示例：身份证号需要 FINANCIAL 级许可且落库加密；其余按缺省规则
        List<FieldRule> rules = List.of(
                new FieldRule("idCard", DataClassification.FINANCIAL, true),
                new FieldRule("payment.cardNo", DataClassification.FINANCIAL, true),
                FieldRule.defaultRule()
        );
        return new PolicyStore(new com.github.xingjianluo.dataprivacygatewayjava.policy.AccessPolicy(
                1, rules, java.time.Instant.now().toString()));
    }

    @Bean
    public KeyStore keyStore() {
        return new KeyStore(KeyStore.initialRing());
    }

    @Bean
    public CryptoService cryptoService(KeyStore keyStore) {
        return new CryptoService(keyStore);
    }

    @Bean
    public MaskingService maskingService() {
        return new MaskingService(MaskStrategy.PARTIAL);
    }

    @Bean
    public RecordStore recordStore() {
        return new RecordStore();
    }

    @Bean
    public AuditStore auditStore(GatewayProperties properties) {
        return new AuditStore(properties.getAuditRetentionDays());
    }

    @Bean
    public AuditService auditService(AuditStore auditStore, GatewayProperties properties) {
        return new AuditService(auditStore, properties.getAuditRetentionDays());
    }

    @Bean
    public CallerDirectory callerDirectory() {
        return CallerDirectory.demo();
    }

    @Bean
    public IngestionService ingestionService(GatewayProperties properties, CryptoService cryptoService) {
        SourceProfile crm = new SourceProfile("crm", "customerId", Map.of(
                "customerId", new FieldSpec("customerId", DataClassification.INTERNAL, true, FieldKind.SCALAR),
                "name", new FieldSpec("name", DataClassification.PII, true, FieldKind.SCALAR),
                "idCard", new FieldSpec("idCard", DataClassification.FINANCIAL, true,
                        FieldKind.SCALAR, true),
                "contacts", new FieldSpec("contacts", DataClassification.PII, false, FieldKind.ARRAY)
        ), false, DataClassification.INTERNAL);
        SourceProfile payment = new SourceProfile("payment", "orderId", Map.of(
                "orderId", new FieldSpec("orderId", DataClassification.INTERNAL, true, FieldKind.SCALAR),
                "payment.cardNo", new FieldSpec("payment.cardNo", DataClassification.FINANCIAL, true,
                        FieldKind.SCALAR, true)
        ), false, DataClassification.INTERNAL);
        CsvSourceAdapter csv = new CsvSourceAdapter("crm-csv",
                new String[]{"customerId", "name", "idCard"});
        return new IngestionService(Map.of("crm", crm, "payment", payment),
                properties.getMaxNodesPerRecord(),
                List.of(csv, new com.github.xingjianluo.dataprivacygatewayjava.ingest.JsonSourceAdapter()),
                cryptoService, properties.getMaxArrayLength(),
                properties.isTruncateOversizeArrays());
    }

    @Bean
    public AccessGateway accessGateway(RecordStore recordStore, PolicyStore policyStore,
                                       CryptoService cryptoService, MaskingService maskingService,
                                       AuditService auditService, GatewayProperties properties) {
        return new AccessGateway(recordStore, policyStore, cryptoService, maskingService,
                auditService, properties);
    }
}
