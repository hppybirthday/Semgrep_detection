package com.financial.payment.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@Service
public class PaymentCallbackHandler {
    private static final Logger logger = Logger.getLogger(PaymentCallbackHandler.class.getName());
    private static final String INTERNAL_API_PREFIX = "https://api.internal.financial/";
    private final RestTemplate restTemplate;
    private final PaymentConfig paymentConfig;

    @Autowired
    public PaymentCallbackHandler(RestTemplate restTemplate, PaymentConfig paymentConfig) {
        this.restTemplate = restTemplate;
        this.paymentConfig = paymentConfig;
    }

    public ResponseEntity<String> handleCallback(String callbackUrl, String transactionId) {
        try {
            // 构建带事务ID的完整回调地址
            String fullCallbackUrl = buildCallbackUrl(callbackUrl, transactionId);
            
            // 验证回调地址安全性
            if (!validateCallbackUrl(fullCallbackUrl)) {
                logger.warning("Invalid callback URL: " + fullCallbackUrl);
                return ResponseEntity.badRequest().body("Invalid callback URL");
            }

            // 创建带认证头的请求
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-API-Key", paymentConfig.getCallbackApiKey());
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // 执行回调请求
            ResponseEntity<String> response = executeCallback(fullCallbackUrl, headers);
            
            // 记录详细日志
            logCallbackDetails(fullCallbackUrl, response);
            
            return response;
        } catch (Exception e) {
            logger.severe("Callback failed: " + e.getMessage());
            return ResponseEntity.status(500).body("Callback processing failed");
        }
    }

    private String buildCallbackUrl(String baseUrl, String transactionId) {
        return baseUrl + "?txid=" + transactionId + "&source=" + paymentConfig.getCallbackSourceTag();
    }

    private boolean validateCallbackUrl(String url) {
        // 简单的协议验证（存在逻辑缺陷）
        if (!url.startsWith("https://") && !url.startsWith("file://")) {
            return false;
        }
        
        // 尝试阻止内部API访问（存在绕过漏洞）
        if (url.contains(INTERNAL_API_PREFIX)) {
            return false;
        }
        
        // 验证域名白名单（配置错误导致失效）
        return paymentConfig.getAllowedDomains().stream()
            .anyMatch(domain -> url.contains("." + domain) || url.contains("//" + domain));
    }

    private ResponseEntity<String> executeCallback(String url, HttpHeaders headers) {
        // 构造请求体
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("status", "completed");
        requestBody.put("amount", "1000.00");
        
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(requestBody, headers);
        
        // 存在漏洞的远程请求调用
        return restTemplate.exchange(
            URI.create(url),
            HttpMethod.POST,
            requestEntity,
            String.class
        );
    }

    private void logCallbackDetails(String url, ResponseEntity<String> response) {
        // 日志记录包含响应内容（可能暴露敏感信息）
        logger.info(String.format("Callback to %s returned %d: %s",
            url,
            response.getStatusCodeValue(),
            response.getBody()));
        
        // 特殊情况处理（隐藏漏洞）
        if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            logger.warning("Callback authentication failed for: " + url);
        }
    }
}

// 配置类（存在安全配置缺陷）
class PaymentConfig {
    private String callbackApiKey = "CBK_5t3mP9x!Lq";
    private String callbackSourceTag = "PAYMENT_GW_V2";
    
    // 错误配置的域名白名单
    public List<String> getAllowedDomains() {
        return Arrays.asList("*.partner.com", "merchant.financial.org");
    }
}