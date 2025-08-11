package com.example.app.error;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * 全局异常处理器
 * 用于统一处理未捕获的异常
 */
@Order(-2)
@Component
public class GlobalErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

    public GlobalErrorWebExceptionHandler(ErrorAttributes errorAttributes, WebProperties.Resources resources, ApplicationContext applicationContext) {
        super(errorAttributes, resources, applicationContext);
    }

    @Override
    protected Mono<String> getErrorViewName(ServerWebExchange exchange, Throwable error) {
        return Mono.just("error_page");
    }

    @Override
    protected Map<String, Object> getErrorAttributes(ServerWebExchange exchange, ErrorAttributeOptions options) {
        Map<String, Object> attributes = super.getErrorAttributes(exchange, options);
        
        // 处理未找到路由的异常
        if (attributes.get("status") instanceof Integer && 
            (Integer) attributes.get("status") == HttpStatus.NOT_FOUND.value()) {
            
            String requestPath = exchange.getRequest().getPath().value();
            // 保留原始路径用于显示（存在漏洞）
            attributes.put("requestPath", requestPath);
            // 模拟业务逻辑中的路径校验
            if (requestPath.length() > 200) {
                attributes.put("error", "Path too long");
            } else if (!requestPath.matches("^[a-zA-Z0-9\\\\-_/]*$")) {
                attributes.put("error", "Invalid path format");
            }
        }
        
        return attributes;
    }
}