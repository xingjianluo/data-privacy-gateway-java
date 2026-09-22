package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 基于 AES/GCM（128-bit tag，96-bit IV）的加解密服务。
 * <ul>
 *   <li>密文令牌自带密钥版本，解密时按版本在密钥环中查找密钥：轮换后旧密文仍可解密。</li>
 *   <li>对已经是合法密文令牌的值再次加密时原样返回，保证加密幂等、不叠加包裹。</li>
 *   <li>版本缺失、版本号无法识别、底层加解密失败分别抛出不同 {@link CryptoException.Kind}，
 *       且只回传领域信息，不把 JCE 异常细节透出给调用方。</li>
 * </ul>
 */
public class CryptoService {

    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final String TRANSFORM = "AES/GCM/NoPadding";

    private final KeyStore keyStore;
    private final SecureRandom random = new SecureRandom();

    public CryptoService(KeyStore keyStore) {
        if (keyStore == null) {
            throw new IllegalArgumentException("keyStore must not be null");
        }
        this.keyStore = keyStore;
    }

    /** 当前密钥环快照（与下一次加解密使用的环一致）。 */
    public KeyRing currentRing() {
        return keyStore.current();
    }

    /**
     * 使用密钥环当前版本加密。
     *
     * @throws CryptoException {@link CryptoException.Kind#ENCRYPTION_FAILED} 底层失败
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new CryptoException(CryptoException.Kind.ENCRYPTION_FAILED, "plaintext is null");
        }
        // 幂等：已是合法密文令牌（版本存在且格式正确）则不再二次包裹
        if (CipherToken.looksLikeToken(plaintext)) {
            CipherToken existing;
            try {
                existing = CipherToken.parse(plaintext);
            } catch (CryptoException e) {
                throw new CryptoException(CryptoException.Kind.ENCRYPTION_FAILED,
                        "value looks like a cipher token but is malformed");
            }
            KeyRing ring = keyStore.current();
            if (ring.version(existing.keyVersion()) != null) {
                return plaintext;
            }
            // 令牌引用的版本在本密钥环中不存在：不允许把"悬空令牌"当作普通明文处理，
            // 明确区分地拒绝，避免密文与版本不一致。
            throw new CryptoException(CryptoException.Kind.KEY_VERSION_MISSING,
                    "cannot keep cipher token: key version " + existing.keyVersion() + " is unknown");
        }

        KeyRing ring = keyStore.current();
        KeyVersion key = ring.current();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key.secretKey(), new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Base64.Encoder enc = Base64.getEncoder();
            return new CipherToken(key.version(), enc.encodeToString(iv), enc.encodeToString(ct)).toWire();
        } catch (GeneralSecurityException e) {
            // 不向外透出底层异常内容
            throw new CryptoException(CryptoException.Kind.ENCRYPTION_FAILED,
                    "encryption failed under key version " + key.version(), e);
        }
    }

    /**
     * 按密文自带版本解密。
     *
     * @throws CryptoException NOT_A_CIPHERTEXT / KEY_VERSION_MISSING / DECRYPTION_FAILED 三者明确可区分
     */
    public String decrypt(String ciphertext) {
        return decrypt(ciphertext, keyStore.current());
    }

    /**
     * 按指定密钥环快照解密，保证一次业务处理中即便发生轮换，
     * 解密所用版本与审计所记版本仍为同一个确定快照。
     *
     * @throws CryptoException NOT_A_CIPHERTEXT / KEY_VERSION_MISSING / DECRYPTION_FAILED 三者明确可区分
     */
    public String decrypt(String ciphertext, KeyRing ring) {
        CipherToken token = CipherToken.parse(ciphertext);
        KeyVersion key = ring.version(token.keyVersion());
        if (key == null) {
            // 版本缺失（密钥环里根本没有这个版本）与"密文损坏/密钥不匹配"必须分开
            throw new CryptoException(CryptoException.Kind.KEY_VERSION_MISSING,
                    "key version " + token.keyVersion() + " is not available for decryption");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key.secretKey(),
                    new GCMParameterSpec(TAG_BITS, token.iv()));
            byte[] pt = cipher.doFinal(token.cipherText());
            return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            // GCM 认证失败说明密文被篡改或用错了密钥版本：统一报 MISMATCH/FAILED，
            // 不透出 JCE 细节
            throw new CryptoException(CryptoException.Kind.DECRYPTION_FAILED,
                    "decryption failed: ciphertext invalid or key version mismatch (v"
                            + token.keyVersion() + ")", e);
        }
    }
}
