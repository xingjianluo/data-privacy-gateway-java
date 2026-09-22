package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Map;

/**
 * 自描述密文信封：{@code {"enc":"AES-GCM-256","v":<keyVersion>,"ct":"<base64 iv|cipher+tag>"}}。
 * 历史密文靠 v 定位历史密钥；版本缺失/错误与密文损坏分别给出不同原因码。
 */
public final class CipherEnvelope {
    public static final String MARKER_ENC = "enc";
    public static final String MARKER_VERSION = "v";
    public static final String MARKER_CT = "ct";
    public static final String SCHEME = "AES-GCM-256";

    private final int keyVersion;
    private final String cipherBase64;

    public CipherEnvelope(int keyVersion, String cipherBase64) {
        this.keyVersion = keyVersion;
        this.cipherBase64 = cipherBase64;
    }

    public int keyVersion() { return keyVersion; }
    public String cipherBase64() { return cipherBase64; }

    public Map<String, Object> toMap() {
        return Map.of(MARKER_ENC, SCHEME, MARKER_VERSION, keyVersion, MARKER_CT, cipherBase64);
    }
}
