package com.github.xingjianluo.dataprivacygatewayjava.ingest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 演示用 CSV 来源适配器：把单行 CSV 文本按绑定来源的表头转换为 Map 载荷，
 * 随后仍走与 JSON 来源完全相同的统一归一流程，保证多来源结论一致。
 */
public class CsvSourceAdapter implements SourceAdapter {

    private final String source;
    private final String[] header;

    public CsvSourceAdapter(String source, String[] header) {
        this.source = source;
        this.header = header.clone();
    }

    public CsvSourceAdapter(String source) {
        this(source, new String[0]);
    }

    @Override
    public boolean supports(String source) {
        return this.source.equals(source);
    }

    @Override
    public Object adapt(Object rawPayload) {
        if (!(rawPayload instanceof String line)) {
            throw new IllegalArgumentException("csv payload must be a single line string");
        }
        String[] parts = line.split(",", -1);
        if (parts.length != header.length) {
            throw new IllegalArgumentException("csv column count does not match header");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < header.length; i++) {
            String v = parts[i].trim();
            map.put(header[i], v.isEmpty() ? null : v);
        }
        return map;
    }
}
