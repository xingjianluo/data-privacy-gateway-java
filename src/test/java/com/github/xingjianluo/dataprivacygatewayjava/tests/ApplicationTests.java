package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ApplicationTests {

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationTests.class);

    @Autowired PrivacyGateway gateway;
    @Autowired PolicyStore policyStore;
    @Autowired KeyStore keyStore;

    @Test
    void contextLoads_andSeeded() {
        LOG.info("[SMOKE] policyVersion={} keyVersion={}", policyStore.current().version(),
                keyStore.currentVersion());
        assertEquals(1, policyStore.current().version());
        assertEquals(1, keyStore.currentVersion());
        var report = gateway.ingest("crm", "smoke-1",
                Map.of("name", "Alice", "phone", "13800001111"), null);
        assertTrue(report.accepted(), report.message());
        AccessResponse resp = gateway.access(
                new AccessRequest("guest", Level.PUBLIC, "smoke-1", false));
        LOG.info("[SMOKE] digest-less view={} reason={}", resp.view(), resp.overallReason());
        assertEquals(ReasonCode.MASKED_INSUFFICIENT_CLEARANCE, resp.overallReason());
        assertEquals("*******1111", resp.view().get("phone"));
    }
}
