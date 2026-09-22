package com.github.xingjianluo.dataprivacygatewayjava.model;

/**
 * 归一化后的统一记录。
 *
 * @param recordId 记录唯一标识
 * @param source   来源系统
 * @param root     归一化数据根节点
 */
public record NormalizedRecord(String recordId, String source, DataNode.Obj root) {

    public NormalizedRecord {
        if (recordId == null || recordId.isBlank()) {
            throw new IllegalArgumentException("recordId must not be blank");
        }
        if (root == null) {
            throw new IllegalArgumentException("root must not be null");
        }
    }
}
