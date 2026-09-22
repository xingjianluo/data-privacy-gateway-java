package com.github.xingjianluo.dataprivacygatewayjava.access;

import com.github.xingjianluo.dataprivacygatewayjava.model.DataNode;

import java.util.List;

/**
 * 一次访问的完整结论：结果数据、整体结论、逐字段依据、策略/密钥版本。
 */
public record AccessResult(DecisionOutcome overall, DataNode.Obj data,
                           List<FieldDecision> decisions, long policyVersion, int keyRingVersion) {
}
