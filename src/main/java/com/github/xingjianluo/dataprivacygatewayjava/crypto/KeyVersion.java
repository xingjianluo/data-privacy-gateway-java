package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import java.time.Instant;

/**
 * 单个密钥版本（不可变）。
 *
 * @param version   版本号（正整数，单调递增）
 * @param secretKey 256-bit AES 密钥
 * @param createdAt 创建时间
 */
public record KeyVersion(int version, javax.crypto.SecretKey secretKey, Instant createdAt) {

    public KeyVersion {
        if (version <= 0) {
            throw new IllegalArgumentException("key version must be positive");
        }
        if (secretKey == null || secretKey.getEncoded() == null || secretKey.getEncoded().length != 32) {
            throw new IllegalArgumentException("key must be a 256-bit AES key");
        }
    }
}
