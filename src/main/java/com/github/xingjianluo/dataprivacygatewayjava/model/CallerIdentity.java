package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.Set;

/**
 * 调用方身份及其在每个数据分类上的访问许可级别。
 */
public record CallerIdentity(String callerId, Set<DataClassification> clearances) {

    public CallerIdentity {
        clearances = clearances == null ? Set.of() : Set.copyOf(clearances);
    }

    /** 是否具备指定分类的原始读取许可。 */
    public boolean canReadRaw(DataClassification classification) {
        return clearances.contains(classification);
    }
}
