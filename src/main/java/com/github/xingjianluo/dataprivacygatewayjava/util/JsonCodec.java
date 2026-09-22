package com.github.xingjianluo.dataprivacygatewayjava.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 最小 JSON 编解码与规范化摘要工具。
 * 统一使用 Jackson；规范化输出按键排序，保证同一输入摘要稳定、可复现。
 */
public final class JsonCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private JsonCodec() {
    }

    public static String toJson(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalArgumentException("JSON 序列化失败", e);
        }
    }

    public static Object parse(String json) {
        try {
            return MAPPER.readValue(json, Object.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("JSON 解析失败", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        Object value = parse(json);
        if (!(value instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("顶层不是 JSON 对象");
        }
        return (Map<String, Object>) map;
    }

    /** 对 JSON 结构做确定性规范化（键排序、无多余空白），便于审计复现。 */
    public static String canonical(Object value) {
        try {
            return CANONICAL.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalArgumentException("JSON 规范化失败", e);
        }
    }

    /** 估算 JSON 结构的 UTF-8 字节规模。 */
    public static int estimatedBytes(Object value) {
        return toJson(value).getBytes(StandardCharsets.UTF_8).length;
    }

    /** 深拷贝纯 JSON 结构，切断调用方引用，避免外部可变状态泄漏到网关内部。 */
    public static Object deepCopy(Object value) {
        if (value == null) {
            return null;
        }
        return parse(toJson(value));
    }
}
