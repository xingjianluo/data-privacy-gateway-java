package com.github.xingjianluo.dataprivacygatewayjava.model;

/** 单个密钥版本的不可变元数据（密钥本体仅在加密组件内部可见）。 */
public final class KeyMaterial {
    private final int version;
    private final String keyBase64;
    private final long createdAt;
    private final boolean enabled;

    public KeyMaterial(int version, String keyBase64, long createdAt, boolean enabled) {
        this.version = version;
        this.keyBase64 = keyBase64;
        this.createdAt = createdAt;
        this.enabled = enabled;
    }

    public int version() { return version; }
    public String keyBase64() { return keyBase64; }
    public long createdAt() { return createdAt; }
    public boolean enabled() { return enabled; }

    // --- Jackson 友好访问器（与方法式访问器并存）---
    public int getVersion() { return version; }
    public String getKeyBase64() { return keyBase64; }
    public long getCreatedAt() { return createdAt; }
    public boolean isEnabled() { return enabled; }
}
