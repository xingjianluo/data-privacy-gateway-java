package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 密文令牌的可解析表示与线路格式：{@code enc:v<版本>:<Base64(IV)>:<Base64(ciphertext+tag)>}。
 * <p>密文自带密钥版本，使历史密文在密钥轮换后仍可按版本找回密钥正确解密。
 *
 * @param keyVersion       加密所用密钥版本
 * @param ivBase64         Base64 编码的初始化向量
 * @param cipherTextBase64 Base64 编码的密文（含 GCM 认证标签）
 */
public record CipherToken(int keyVersion, String ivBase64, String cipherTextBase64) {

    public static final String PREFIX = "enc:v";

    private static final Pattern WIRE =
            Pattern.compile("^enc:v(\\d{1,9}):([A-Za-z0-9+/=_-]+):([A-Za-z0-9+/=_-]+)$");

    public CipherToken {
        if (keyVersion <= 0) {
            throw new CryptoException(CryptoException.Kind.NOT_A_CIPHERTEXT,
                    "cipher token key version must be positive");
        }
        if (ivBase64 == null || cipherTextBase64 == null) {
            throw new CryptoException(CryptoException.Kind.NOT_A_CIPHERTEXT,
                    "cipher token parts must not be null");
        }
    }

    public String toWire() {
        return PREFIX + keyVersion + ":" + ivBase64 + ":" + cipherTextBase64;
    }

    public byte[] iv() {
        return Base64.getDecoder().decode(ivBase64);
    }

    public byte[] cipherText() {
        return Base64.getDecoder().decode(cipherTextBase64);
    }

    public static boolean looksLikeToken(String value) {
        return value != null && WIRE.matcher(value).matches();
    }

    /**
     * 解析密文令牌。格式错误抛 {@link CryptoException#NOT_A_CIPHERTEXT}，
     * 不向调用方透出底层解析异常细节。
     */
    public static CipherToken parse(String wire) {
        if (wire == null) {
            throw new CryptoException(CryptoException.Kind.NOT_A_CIPHERTEXT, "value is null");
        }
        Matcher m = WIRE.matcher(wire);
        if (!m.matches()) {
            throw new CryptoException(CryptoException.Kind.NOT_A_CIPHERTEXT,
                    "value is not a well-formed cipher token");
        }
        try {
            int version = Integer.parseInt(m.group(1));
            String iv = m.group(2);
            String ct = m.group(3);
            // 提前做一次 Base64 校验，非法编码按非密文处理而非透出 IllegalArgumentException
            Base64.getDecoder().decode(iv);
            Base64.getDecoder().decode(ct);
            return new CipherToken(version, iv, ct);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.Kind.NOT_A_CIPHERTEXT,
                    "cipher token has malformed base64 parts");
        }
    }
}
