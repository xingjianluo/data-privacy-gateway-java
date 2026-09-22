package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 密钥内存存储。
 * <p>密钥环以不可变 {@link KeyRing} 快照原子发布：读者要么读到完整旧环，
 * 要么读到完整新环，不会出现"当前版本已变、历史版本表半更新"的状态。
 * 轮换只增加版本，旧版本永久保留在环内用于历史密文解密。
 */
public class KeyStore {

    private final AtomicReference<KeyRing> ring;

    public KeyStore(KeyRing initial) {
        if (initial == null) {
            throw new IllegalArgumentException("initial key ring must not be null");
        }
        this.ring = new AtomicReference<>(initial);
    }

    /** 读取当前密钥环快照（确定版本，不受并发轮换影响）。 */
    public KeyRing current() {
        return ring.get();
    }

    /**
     * 轮换密钥：生成新版本号（当前最大版本 + 1）的 AES-256 密钥并设为当前版本，
     * 旧版本全部保留。多个线程并发轮换时版本号仍然连续且不丢版本。
     */
    public KeyRing rotate(String rotatedAt) {
        while (true) {
            KeyRing old = ring.get();
            int newVersion = old.versions().keySet().stream().mapToInt(Integer::intValue).max().orElse(0) + 1;
            KeyVersion generated = generateKey(newVersion, Instant.now());
            Map<Integer, KeyVersion> merged = new LinkedHashMap<>(old.versions());
            merged.put(newVersion, generated);
            KeyRing next = new KeyRing(newVersion, merged,
                    rotatedAt == null ? Instant.now().toString() : rotatedAt);
            if (ring.compareAndSet(old, next)) {
                return next;
            }
        }
    }

    /** 生成一个初始密钥环（仅含 v1）。 */
    public static KeyRing initialRing() {
        KeyVersion v1 = generateKey(1, Instant.now());
        return new KeyRing(1, Map.of(1, v1), Instant.now().toString());
    }

    static KeyVersion generateKey(int version, Instant createdAt) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return new KeyVersion(version, kg.generateKey(), createdAt);
        } catch (NoSuchAlgorithmException e) {
            // AES 为 JDK 必备算法；到这里说明运行环境损坏，包装为领域异常，不透出底层细节
            throw new CryptoException(CryptoException.Kind.ENCRYPTION_FAILED,
                    "key generation unavailable in this runtime", e);
        }
    }
}
