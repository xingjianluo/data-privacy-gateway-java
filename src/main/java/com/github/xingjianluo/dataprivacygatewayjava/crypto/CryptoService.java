package com.github.xingjianluo.dataprivacygatewayjava.crypto;

import com.github.xingjianluo.dataprivacygatewayjava.model.CipherEnvelope;

/** 版本化加解密抽象；实现须吞掉底层异常并转换为受控原因码。 */
public interface CryptoService {

    /** 用当前启用版本加密；传入已是信封时原样返回（幂等，不叠加）。 */
    CipherEnvelope encrypt(String plaintext);

    /** 按信封版本解密历史 / 当前密文。 */
    String decrypt(CipherEnvelope envelope);

    int currentVersion();
}
