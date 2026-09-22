package com.github.xingjianluo.dataprivacygatewayjava.store;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.KeyMaterial;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.KeyGenerator;

/**
 * 内存密钥库：
 * <ul>
 *   <li>轮换 = 生成新版本并原子切换 current；旧版本全部保留，历史密文始终可解密。</li>
 *   <li>读路径无锁；发布路径同步，保证版本号唯一递增。</li>
 * </ul>
 */
@Component
public class KeyStore {

    private final ConcurrentMap<Integer, KeyMaterial> versions = new ConcurrentHashMap<>();
    private final AtomicInteger seq = new AtomicInteger(0);
    private final AtomicReference<KeyMaterial> current = new AtomicReference<>();

    public KeyStore() {
    }

    /** 新增一个 AES-256 密钥版本并原子设为当前版本。 */
    public KeyMaterial rotate(String keyBase64) {
        synchronized (this) {
            int v = seq.incrementAndGet();
            String material = keyBase64 != null ? keyBase64 : generateAes256KeyBase64();
            KeyMaterial km = new KeyMaterial(v, material, System.currentTimeMillis(), true);
            versions.put(v, km);
            current.set(km);
            return km;
        }
    }

    public KeyMaterial current() {
        return current.get();
    }

    /**
     * 按版本取密钥。
     * @return 密钥材料；版本不存在或已禁用返回 null（由上层区分 KEY_VERSION_MISSING）
     */
    public KeyMaterial byVersion(int version) {
        KeyMaterial km = versions.get(version);
        if (km == null || !km.enabled()) {
            return null;
        }
        return km;
    }

    public int currentVersion() {
        KeyMaterial km = current.get();
        return km == null ? -1 : km.version();
    }

    public List<KeyMaterial> allVersions() {
        List<KeyMaterial> list = new ArrayList<>(versions.values());
        list.sort((a, b) -> Integer.compare(a.version(), b.version()));
        return List.copyOf(list);
    }

    private static String generateAes256KeyBase64() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
        } catch (Exception e) {
            // 密钥生成是本地基础设施问题，不把底层异常透出给调用方
            throw new GatewayException(ReasonCode.CRYPTO_FAILURE, "密钥生成失败", e);
        }
    }
}
