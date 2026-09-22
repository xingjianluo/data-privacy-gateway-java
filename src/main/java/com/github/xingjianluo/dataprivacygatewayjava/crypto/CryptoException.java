package com.github.xingjianluo.dataprivacygatewayjava.crypto;

/**
 * 加解密领域异常：密钥版本缺失 / 版本不匹配 / 底层加解密失败必须可区分，
 * 且底层异常细节不得直接透出给调用方。
 */
public class CryptoException extends RuntimeException {

    public enum Kind {
        KEY_VERSION_MISSING,
        KEY_VERSION_MISMATCH,
        NOT_A_CIPHERTEXT,
        ENCRYPTION_FAILED,
        DECRYPTION_FAILED
    }

    private final Kind kind;

    public CryptoException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public CryptoException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
