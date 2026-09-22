package com.github.xingjianluo.dataprivacygatewayjava.bootstrap;

import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 播种：密钥 v1 与策略 v1。
 * 字段逻辑名在嵌套/数组/包装/别名下统一生效：
 * phone（别名 mobile）需 CONFIDENTIAL；idCard 需 RESTRICTED；email 需 INTERNAL。
 */
@Component
@Order(1)
public class SeedDataInitializer implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(SeedDataInitializer.class);

    private final PolicyStore policyStore;
    private final KeyStore keyStore;

    public SeedDataInitializer(PolicyStore policyStore, KeyStore keyStore) {
        this.policyStore = policyStore;
        this.keyStore = keyStore;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (keyStore.current() == null) {
            keyStore.rotate(null);
            LOG.info("已播种初始密钥版本 v{}", keyStore.currentVersion());
        }
        if (policyStore.current() == null) {
            List<FieldRule> rules = List.of(
                    new FieldRule("phone", Level.CONFIDENTIAL, "TAIL4", List.of("mobile", "telephone")),
                    new FieldRule("idCard", Level.RESTRICTED, "FULL", List.of("identityNo", "ssn")),
                    new FieldRule("email", Level.INTERNAL, "EMAIL", List.of("mail")),
                    new FieldRule("name", Level.INTERNAL, "FULL", List.of("fullName", "userName"))
            );
            var policy = policyStore.publish(rules);
            LOG.info("已播种初始策略版本 v{}，规则数 {}", policy.version(), policy.rules().size());
        }
    }
}
