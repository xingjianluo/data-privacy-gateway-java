package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.CipherToken;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoException;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyRing;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyVersion;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 密钥轮换：轮换后旧密文仍可解密；新版本密文用新版本；版本缺失 / 用错 / 篡改必须可区分。
 */
class CryptoRotationTest {

    private static final Logger log = LoggerFactory.getLogger(CryptoRotationTest.class);

    @Test
    void oldCiphertextRemainsDecryptableAfterRotation() {
        KeyStore store = new KeyStore(KeyStore.initialRing());
        CryptoService crypto = new CryptoService(store);

        String oldCipher = crypto.encrypt("身份证-110101199001011234");
        int oldVersion = CipherToken.parse(oldCipher).keyVersion();
        log.info("[输入摘要] plaintext=<idCard 18位>, cipher={}...", abbreviate(oldCipher));

        KeyRing after = store.rotate(Instant.now().toString());
        assertEquals(2, after.currentVersion(), "轮换后当前版本应为 v2");
        assertEquals(2, after.versions().size(), "历史版本必须保留");

        String newCipher = crypto.encrypt("新数据-2026");
        assertEquals(2, CipherToken.parse(newCipher).keyVersion(), "新密文必须用当前 v2");

        String decryptedOld = crypto.decrypt(oldCipher);
        String decryptedNew = crypto.decrypt(newCipher);
        assertEquals("身份证-110101199001011234", decryptedOld, "旧密文轮换后必须仍可解密");
        assertEquals("新数据-2026", decryptedNew);
        log.info("[判定依据] oldCipher=v{} -> 解密成功; newCipher=v{} -> 解密成功; ringVersions={}",
                oldVersion, 2, after.versionList());
    }

    @Test
    void missingVersionIsDistinctFromMismatchAndTamper() {
        KeyStore store = new KeyStore(KeyStore.initialRing());
        CryptoService crypto = new CryptoService(store);
        String cipherV1 = crypto.encrypt("secret-value");

        // 构造一个只含 v2 的新密钥环（模拟版本缺失环境）
        KeyVersion v2 = KeyStore.initialRing().current(); // 借用一把密钥
        KeyRing ringWithoutV1 = new KeyRing(2, Map.of(2, new KeyVersion(2, v2.secretKey(), Instant.now())),
                Instant.now().toString());
        KeyStore otherStore = new KeyStore(ringWithoutV1);
        CryptoService cryptoOther = new CryptoService(otherStore);

        CryptoException missing = assertThrows(CryptoException.class,
                () -> cryptoOther.decrypt(cipherV1));
        assertEquals(CryptoException.Kind.KEY_VERSION_MISSING, missing.kind(),
                "版本不存在必须与解密失败明确区分");
        log.info("[判定依据] 版本缺失 -> kind={}, message={}", missing.kind(), missing.getMessage());

        // 篡改密文（GCM 认证失败）必须报 DECRYPTION_FAILED，且不泄漏底层异常细节
        CipherToken token = CipherToken.parse(cipherV1);
        byte[] ct = token.cipherText();
        ct[ct.length - 1] ^= 0x01;
        String tampered = new CipherToken(1, token.ivBase64(),
                java.util.Base64.getEncoder().encodeToString(ct)).toWire();
        CryptoException failed = assertThrows(CryptoException.class, () -> crypto.decrypt(tampered));
        assertEquals(CryptoException.Kind.DECRYPTION_FAILED, failed.kind());
        assertFalse(failed.getMessage().contains("AEADBadTag"), "底层 JCE 异常细节不得透出");
        log.info("[判定依据] 密文篡改 -> kind={}, message={}", failed.kind(), failed.getMessage());

        // 非密文输入
        CryptoException notToken = assertThrows(CryptoException.class,
                () -> crypto.decrypt("plain-not-cipher"));
        assertEquals(CryptoException.Kind.NOT_A_CIPHERTEXT, notToken.kind());
        log.info("[判定依据] 非密文 -> kind={}", notToken.kind());
    }

    @Test
    void encryptIsIdempotentOnCiphertext() {
        KeyStore store = new KeyStore(KeyStore.initialRing());
        CryptoService crypto = new CryptoService(store);
        String c1 = crypto.encrypt("hello");
        String c2 = crypto.encrypt(c1);
        assertEquals(c1, c2, "对已加密值再次加密必须原样返回，不得叠加包裹");
        log.info("[输入摘要] double-encrypt 输入与输出相等: {}", c1.equals(c2));
    }

    private static String abbreviate(String s) {
        return s.length() > 24 ? s.substring(0, 24) + "..." : s;
    }
}
