package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import java.util.List;
import java.util.Map;

/**
 * 某一版本的密钥环快照：含当前版本与全部历史版本，保证轮换后旧密文仍可解密。
 */
public record KeyRing(int currentVersion, Map<Integer, KeyVersion> versions, String rotatedAt) {

    public KeyRing {
        versions = Map.copyOf(versions);
        if (!versions.containsKey(currentVersion)) {
            throw new IllegalArgumentException("current key version missing from ring");
        }
    }

    public KeyVersion current() {
        return versions.get(currentVersion);
    }

    public KeyVersion version(int v) {
        return versions.get(v);
    }

    public List<Integer> versionList() {
        return versions.keySet().stream().sorted().toList();
    }
}
