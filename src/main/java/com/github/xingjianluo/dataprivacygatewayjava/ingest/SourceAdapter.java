package com.github.xingjianluo.dataprivacygatewayjava.ingest;

import com.github.xingjianluo.dataprivacygatewayjava.model.IngestionResult;

/**
 * 来源适配器：负责把某来源的原始记录翻译为统一的 JSON 风格载荷后走统一归一流程。
 */
public interface SourceAdapter {

    boolean supports(String source);

    /** 适配器级预处理（如 CSV 行 -> Map），默认返回原值。 */
    default Object adapt(Object rawPayload) {
        return rawPayload;
    }

    /** 便利方法：预处理后直接接入（由 {@link IngestionService} 在实现中编排）。 */
    default IngestionResult toResult(Object rawPayload) {
        return IngestionResult.reject(java.util.Map.of("(adapter)",
                com.github.xingjianluo.dataprivacygatewayjava.model.RejectionReason.MALFORMED_RECORD));
    }
}
