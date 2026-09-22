package com.github.xingjianluo.dataprivacygatewayjava.masking;

/**
 * 脱敏服务。
 * <ul>
 *   <li>{@link MaskStrategy#FULL}：整值替换为 {@value #MASK_MARKER}。</li>
 *   <li>{@link MaskStrategy#PARTIAL}：保留首字符，其余打码（短串全码）。</li>
 *   <li>{@link MaskStrategy#LAST4}：仅保留后 4 位，其余打码。</li>
 * </ul>
 * 对已经脱敏的值再次脱敏必须幂等：带 {@value #MASK_MARKER} 前缀的值直接原样返回，
 * 不叠加变形。
 */
public class MaskingService {

    public static final String MASK_MARKER = "***";

    private final MaskStrategy defaultStrategy;

    public MaskingService(MaskStrategy defaultStrategy) {
        this.defaultStrategy = defaultStrategy == null ? MaskStrategy.FULL : defaultStrategy;
    }

    public MaskStrategy defaultStrategy() {
        return defaultStrategy;
    }

    public String mask(String value) {
        return mask(value, defaultStrategy);
    }

    public String mask(String value, MaskStrategy strategy) {
        if (value == null) {
            return null;
        }
        // 幂等：已脱敏值不再二次变形（无论由哪种策略产生）
        if (isMasked(value)) {
            return value;
        }
        MaskStrategy s = strategy == null ? defaultStrategy : strategy;
        return switch (s) {
            case FULL -> MASK_MARKER;
            case PARTIAL -> partial(value);
            case LAST4 -> last4(value);
        };
    }

    /**
     * 判断一个值是否已经是脱敏形态。脱敏产物均以 {@value #MASK_MARKER} 开头，
     * 普通业务值不会以该前缀开头（接入层不做限制，判定层以此保证幂等）。
     */
    public boolean isMasked(String value) {
        return value != null && value.startsWith(MASK_MARKER);
    }

    private static String partial(String value) {
        if (value.length() <= 1) {
            return MASK_MARKER;
        }
        return MASK_MARKER + value.charAt(0) + "*".repeat(Math.max(0, value.length() - 1));
    }

    private static String last4(String value) {
        if (value.length() <= 4) {
            return MASK_MARKER + "*".repeat(value.length());
        }
        return MASK_MARKER + "*".repeat(value.length() - 4) + value.substring(value.length() - 4);
    }
}
