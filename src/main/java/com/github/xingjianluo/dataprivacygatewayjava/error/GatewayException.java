package com.github.xingjianluo.dataprivacygatewayjava.error;

import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;

/** 领域异常：只携带稳定原因码与受控信息，绝不透传底层异常细节。 */
public class GatewayException extends RuntimeException {
    private final ReasonCode code;

    public GatewayException(ReasonCode code, String message) {
        super(message);
        this.code = code;
    }

    public GatewayException(ReasonCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ReasonCode code() {
        return code;
    }
}
