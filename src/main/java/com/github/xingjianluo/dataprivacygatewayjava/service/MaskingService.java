package com.github.xingjianluo.dataprivacygatewayjava.service;

import com.github.xingjianluo.dataprivacygatewayjava.crypto.AesGcmCryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import org.springframework.stereotype.Service;

/**
 * 脱敏器。
 * 幂等保证：
 * <ul>
 *   <li>值已经是脱敏令牌 {@link #MASK_TOKEN} 时原样返回，不叠加；</li>
 *   <li>值是密文信封时不做任何变形（脱敏/加密互不可叠加）；</li>
 *   <li>重复脱敏同一明文始终得到同一结果（固定令牌或确定性保留规则）。</li>
 * </ul>
 */
@Service
public class MaskingService {

    public static final String MASK_TOKEN = "***MASKED***";

    public Object mask(Object value, FieldRule rule) {
        if (value == null) {
            return null;
        }
        if (AesGcmCryptoService.isEnvelope(value)) {
            // 密文不参与脱敏变形
            return value;
        }
        String pattern = rule == null ? "FULL" : rule.maskPattern();
        if (pattern == null || pattern.isBlank()) {
            pattern = "FULL";
        }
        if (!(value instanceof String s)) {
            // 非字符串敏感值（如数字证件号）统一以固定令牌脱敏，结果确定
            return MASK_TOKEN;
        }
        if (MASK_TOKEN.equals(s)) {
            return MASK_TOKEN;
        }
        return switch (pattern) {
            case "TAIL4" -> tail4(s);
            case "EMAIL" -> email(s);
            default -> MASK_TOKEN;
        };
    }

    private static String tail4(String s) {
        if (s.length() <= 4) {
            return MASK_TOKEN;
        }
        return "*".repeat(Math.min(s.length() - 4, 8)) + s.substring(s.length() - 4);
    }

    private static String email(String s) {
        int at = s.indexOf('@');
        if (at <= 0) {
            return MASK_TOKEN;
        }
        String name = s.substring(0, at);
        String domain = s.substring(at);
        String kept = name.length() <= 1 ? "*" : name.charAt(0) + "***";
        return kept + domain;
    }
}
