package com.github.xingjianluo.dataprivacygatewayjava.web;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** 统一异常出口：只暴露受控原因码与受控消息，绝不向调用方透传底层堆栈。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(GatewayException.class)
    public ResponseEntity<Map<String, Object>> handleGateway(GatewayException ex) {
        HttpStatus status = switch (ex.code()) {
            case DENIED_UNAUTHORIZED_RAW_READ,
                 GRANT_CALLER_MISMATCH, GRANT_EXPIRED, GRANT_REVOKED,
                 GRANT_SCOPE_VIOLATION -> HttpStatus.FORBIDDEN;
            case GRANT_NOT_FOUND, GRANT_INVALID,
                 BAD_REQUEST, MALFORMED_ENVELOPE -> HttpStatus.BAD_REQUEST;
            case KEY_VERSION_MISSING, POLICY_VERSION_NOT_FOUND -> HttpStatus.CONFLICT;
            case REQUEST_TIMEOUT -> HttpStatus.REQUEST_TIMEOUT;
            case REJECT_BATCH_TOO_LARGE -> HttpStatus.PAYLOAD_TOO_LARGE;
            case DUPLICATE_REQUEST -> HttpStatus.CONFLICT;
            default -> HttpStatus.UNPROCESSABLE_ENTITY;
        };
        LOG.warn("[GATEWAY-ERROR] code={} message={}", ex.code(), ex.getMessage());
        return ResponseEntity.status(status).body(Map.of(
                "ok", false,
                "reason", ex.code().name(),
                "message", ex.getMessage() == null ? "" : ex.getMessage()));
    }
}
