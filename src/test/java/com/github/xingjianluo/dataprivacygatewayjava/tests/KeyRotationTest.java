package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.CipherEnvelope;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
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
class KeyRotationTest {

    private static final Logger LOG = LoggerFactory.getLogger(KeyRotationTest.class);

    @Autowired PrivacyGateway gateway;
    @Autowired KeyStore keyStore;
    @Autowired AesGcmCryptoService crypto;

    @Test
    void old_ciphertext_decrypts_after_rotation() {
        gateway.ingest("crm", "kr-1", Map.of("phone", "13800001111"), null);
        gateway.encryptFields("kr-1", List.of("phone"));
        int oldVersion = keyStore.currentVersion();
        // 轮换
        var km = keyStore.rotate(null);
        LOG.info("[ROTATION] oldV={} newV={}", oldVersion, km.version());
        assertEquals(oldVersion + 1, km.version());

        // 轮换后旧密文仍可解密（信封自带版本 v=oldVersion）
        Map<String, Object> decrypted = gateway.decryptRecord("ops", "kr-1");
        LOG.info("[ROTATION] 旧密文解密结果={} 依据: 信封版本 v{} -> 历史密钥", decrypted, oldVersion);
        assertEquals("13800001111", decrypted.get("phone"));

        // 再次加密是幂等的：已经是信封的值不会被新版本重新包裹
        int changed = gateway.encryptFields("kr-1", List.of("phone"));
        LOG.info("[ROTATION] 再加密变更标量数={}（期望 0，已加密值保持原信封版本 v{}）", changed, oldVersion);
        assertEquals(0, changed);
        Map<String, Object> still = gateway.decryptRecord("ops", "kr-1");
        assertEquals("13800001111", still.get("phone"));
    }

    @Test
    void missing_version_and_wrong_version_are_distinct() {
        CipherEnvelope env = crypto.encrypt("secret");
        int v = env.keyVersion();
        // 模拟版本彻底缺失：构造一个版本号不存在的信封
        CipherEnvelope missing = new CipherEnvelope(999_999, env.cipherBase64());
        GatewayException e1 = assertThrows(GatewayException.class, () -> crypto.decrypt(missing));
        LOG.warn("[KEY-CASE=missing] code={} message={}", e1.code(), e1.getMessage());
        assertEquals(ReasonCode.KEY_VERSION_MISSING, e1.code());

        // 用错版本：显式指定期望版本与信封版本不一致
        int expected = v == 1 ? 2 : 1;
        GatewayException e2 = assertThrows(GatewayException.class,
                () -> crypto.decrypt(env, expected));
        LOG.warn("[KEY-CASE=mismatch] code={} message={}", e2.code(), e2.getMessage());
        assertEquals(ReasonCode.KEY_VERSION_MISMATCH, e2.code());

        // 密文损坏：底层 AEAD 异常不透出，统一为 CRYPTO_FAILURE
        CipherEnvelope corrupted = new CipherEnvelope(v, "aaaa" + env.cipherBase64().substring(4));
        GatewayException e3 = assertThrows(GatewayException.class, () -> crypto.decrypt(corrupted));
        LOG.warn("[KEY-CASE=crypto] code={} message={}", e3.code(), e3.getMessage());
        assertEquals(ReasonCode.CRYPTO_FAILURE, e3.code());
    }

    @Test
    void malformed_envelope_is_reported_as_malformed() {
        GatewayException e = assertThrows(GatewayException.class,
                () -> AesGcmCryptoService.fromMap(Map.of("enc", CipherEnvelope.SCHEME, "v", 1)));
        LOG.warn("[KEY-CASE=malformed] code={}", e.code());
        assertEquals(ReasonCode.MALFORMED_ENVELOPE, e.code());
    }
}
