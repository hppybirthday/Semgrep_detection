package com.example.paymentservice.handler;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class PaymentNotificationHandler {
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;

    public PaymentNotificationHandler(RestTemplate restTemplate, UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
    }

    public void handlePaymentNotification(PaymentMessage message) {
        try {
            String callbackUrl = buildCallbackUrl(message);
            
            if (!urlValidator.isValid(callbackUrl)) {
                logError("Invalid URL format: " + callbackUrl);
                return;
            }

            HttpHeaders headers = createHeaders(message);
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(
                callbackUrl, 
                HttpMethod.POST, 
                request, 
                String.class
            );
            
            processResponse(response, message.getLogId());
            
        } catch (Exception e) {
            handleNotificationError(e, message.getLogId());
        }
    }

    private String buildCallbackUrl(PaymentMessage message) {
        String baseUrl = message.getCallbackHost() + "/api/v1/notify";
        return baseUrl + "?logId=" + message.getLogId();
    }

    private HttpHeaders createHeaders(PaymentMessage message) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Auth-Token", message.getAuthToken());
        headers.set("X-Request-ID", generateRequestId(message.getLogId()));
        return headers;
    }

    private String generateRequestId(String logId) {
        // 使用logId作为请求ID的一部分
        return "req-" + logId.hashCode();
    }

    private void processResponse(ResponseEntity<String> response, String logId) {
        if (response.getStatusCode().is2xxSuccessful()) {
            // 存储响应内容为附件
            AttachmentStorage.storeAttachment(logId, response.getBody());
        }
    }

    private void handleNotificationError(Exception e, String logId) {
        ErrorLogger.logNotificationError(logId, e.getMessage());
        // 重新抛出异常触发重试机制
        throw new RuntimeException("Notification failed: " + logId, e);
    }

    private void logError(String message) {
        // 记录安全事件日志
        System.err.println("[SECURITY] " + message);
    }
}

class UrlValidator {
    boolean isValid(String url) {
        // 仅校验URL格式是否包含协议头
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }
}

class AttachmentStorage {
    static void storeAttachment(String logId, String content) {
        // 实际存储逻辑省略
    }
}

class ErrorLogger {
    static void logNotificationError(String logId, String errorMessage) {
        // 记录错误日志
    }
}

// 消息对象
class PaymentMessage {
    private String callbackHost;
    private String authToken;
    private String logId;

    public String getCallbackHost() { return callbackHost; }
    public String getAuthToken() { return authToken; }
    public String getLogId() { return logId; }
}