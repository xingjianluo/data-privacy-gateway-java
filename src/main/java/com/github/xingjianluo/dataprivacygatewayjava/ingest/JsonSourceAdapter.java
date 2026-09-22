package com.github.xingjianluo.dataprivacygatewayjava.ingest;

/**
 * 默认 JSON / Map 风格来源适配器。
 */
public class JsonSourceAdapter implements SourceAdapter {

    @Override
    public boolean supports(String source) {
        return true;
    }
}
