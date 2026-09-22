package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.CipherEnvelope;
import com.github.xingjianluo.dataprivacygatewayjava.model.KeyMaterial;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * AES-GCM-256 版本化加解密。
 * 密文布局：base64( IV[12] || ciphertext+tag[16] )。
 * 信封结构由 {@link CipherEnvelope} 自描述，轮换后旧密文按信封中的版本取历史密钥解密。
 * 底层异常一律转换为 {@link GatewayException} + 稳定原因码，不向调用方透出。
 */
@Component
public class AesGcmCryptoService implements CryptoService {

    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final KeyStore keyStore;
    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getEncoder();
    private final Base64.Decoder decoder = Base64.getDecoder();

    public AesGcmCryptoService(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public CipherEnvelope encrypt(String plaintext) {
        KeyMaterial km = keyStore.current();
        if (km == null) {
            throw new GatewayException(ReasonCode.KEY_VERSION_MISSING, "当前无可用密钥版本");
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(decoder.decode(km.keyBase64()), "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] packed = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, packed, 0, iv.length);
            System.arraycopy(ct, 0, packed, iv.length, ct.length);
            return new CipherEnvelope(km.version(), encoder.encodeToString(packed));
        } catch (GatewayException e) {
            throw e;
        } catch (Exception e) {
            // 不向上透出 AEAD/密钥细节
            throw new GatewayException(ReasonCode.CRYPTO_FAILURE, "加密失败");
        }
    }

    @Override
    public String decrypt(CipherEnvelope envelope) {
        return decrypt(envelope, null);
    }

    /**
     * 按信封版本解密；expectedVersion 非空时必须与信封版本一致，否则判为用错版本。
     */
    public String decrypt(CipherEnvelope envelope, Integer expectedVersion) {
        if (envelope == null) {
            throw new GatewayException(ReasonCode.MALFORMED_ENVELOPE, "密文信封为空");
        }
        if (expectedVersion != null && expectedVersion != envelope.keyVersion()) {
            throw new GatewayException(ReasonCode.KEY_VERSION_MISMATCH,
                    "密钥版本用错：期望 v" + expectedVersion + "，密文为 v" + envelope.keyVersion());
        }
        KeyMaterial km = keyStore.byVersion(envelope.keyVersion());
        if (km == null) {
            // 版本在库中不存在（已彻底清除/从不存在）——与“用错版本”明确区分
            throw new GatewayException(ReasonCode.KEY_VERSION_MISSING,
                    "密钥版本缺失：v" + envelope.keyVersion());
        }
        try {
            byte[] packed = decoder.decode(envelope.cipherBase64());
            if (packed.length <= IV_LENGTH) {
                throw new GatewayException(ReasonCode.MALFORMED_ENVELOPE, "密文体过短");
            }
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(packed, 0, iv, 0, IV_LENGTH);
            byte[] ct = new byte[packed.length - IV_LENGTH];
            System.arraycopy(packed, IV_LENGTH, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(decoder.decode(km.keyBase64()), "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (GatewayException e) {
            throw e;
        } catch (Exception e) {
            // 认证失败/填充损坏等：给出受控结论，不泄漏底层信息
            throw new GatewayException(ReasonCode.CRYPTO_FAILURE,
                    "解密失败（密文损坏或密钥不匹配）");
        }
    }

    @Override
    public int currentVersion() {
        return keyStore.currentVersion();
    }

    /** 判断一个 JSON 值是否为密文信封（幂等处理的前提）。 */
    public static boolean isEnvelope(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            return false;
        }
        Object enc = map.get(CipherEnvelope.MARKER_ENC);
        Object v = map.get(CipherEnvelope.MARKER_VERSION);
        Object ct = map.get(CipherEnvelope.MARKER_CT);
        return CipherEnvelope.SCHEME.equals(enc) && v instanceof Number && ct instanceof String;
    }

    /** 从 Map 构造信封；结构不完整给出 MALFORMED_ENVELOPE。 */
    public static CipherEnvelope fromMap(Map<?, ?> map) {
        Object enc = map.get(CipherEnvelope.MARKER_ENC);
        Object v = map.get(CipherEnvelope.MARKER_VERSION);
        Object ct = map.get(CipherEnvelope.MARKER_CT);
        if (!CipherEnvelope.SCHEME.equals(enc) || !(v instanceof Number) || !(ct instanceof String s)) {
            throw new GatewayException(ReasonCode.MALFORMED_ENVELOPE, "密文信封结构不完整");
        }
        int version = ((Number) v).intValue();
        if (s.isBlank()) {
            throw new GatewayException(ReasonCode.MALFORMED_ENVELOPE, "密文体为空");
        }
        return new CipherEnvelope(version, s);
    }
}
