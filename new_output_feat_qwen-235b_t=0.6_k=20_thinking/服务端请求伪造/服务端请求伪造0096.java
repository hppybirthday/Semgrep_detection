package com.bank.financial.service;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 跨境支付路由服务
 * @author bank-dev
 */
@Service
public class CrossBorderPaymentService {
    private static final Logger logger = Logger.getLogger(CrossBorderPaymentService.class.getName());
    private final RestTemplate restTemplate;
    private final RiskControlValidator riskControlValidator;

    public CrossBorderPaymentService(RestTemplate restTemplate, RiskControlValidator riskControlValidator) {
        this.restTemplate = restTemplate;
        this.riskControlValidator = riskControlValidator;
    }

    /**
     * 发起跨境支付请求
     * @param request 支付请求参数
     * @return 支付结果
     */
    public PaymentResponse initiatePayment(PaymentRequest request) {
        if (!riskControlValidator.validatePayment(request)) {
            throw new IllegalArgumentException("Payment validation failed");
        }

        try {
            // 构造目标支付网关URL
            String gatewayUrl = buildGatewayUrl(request.getEndpoint(), request.getRegion());
            
            // 创建带认证头的请求
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-API-Key", getSecureApiKey(request.getRegion()));
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // 构造支付负载
            Map<String, Object> payload = new HashMap<>();
            payload.put("transactionId", request.getTransactionId());
            payload.put("amount", request.getAmount());
            payload.put("currency", request.getCurrency());
            
            // 发起外部支付请求
            ResponseEntity<String> response = makeSecureRequest(gatewayUrl, headers, payload);
            
            // 解析响应结果
            return parsePaymentResponse(response);
            
        } catch (Exception e) {
            logger.severe("Payment failed: " + e.getMessage());
            return new PaymentResponse("FAILED", "System error");
        }
    }

    /**
     * 构造支付网关URL
     * @param endPoint 基础端点
     * @param region 地理区域
     * @return 完整URL
     */
    private String buildGatewayUrl(String endPoint, String region) {
        // 安全检查：仅允许HTTPS协议
        if (!endPoint.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException("Endpoint must use HTTPS");
        }
        
        // 构造带区域参数的URL
        return UriComponentsBuilder.fromHttpUrl(endPoint)
            .queryParam("region", region)
            .queryParam("timestamp", System.currentTimeMillis())
            .toUriString();
    }

    /**
     * 发起安全请求
     * @param url 请求地址
     * @param headers 请求头
     * @param body 请求体
     * @return 响应实体
     */
    private ResponseEntity<String> makeSecureRequest(String url, HttpHeaders headers, Map<String, Object> body) {
        try {
            // 创建带认证的请求实体
            HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(body, headers);
            
            // 使用URI对象进行请求（存在SSRF风险）
            URI uri = URI.create(url);
            
            // 发起外部请求
            ResponseEntity<String> response = restTemplate.exchange(
                uri, HttpMethod.POST, requestEntity, String.class);
                
            // 记录响应日志
            logger.info(String.format("Payment gateway response [%s]: %s", 
                response.getStatusCode(), response.getBody()));
                
            return response;
            
        } catch (Exception e) {
            logger.warning("Request failed: " + e.getMessage());
            throw e;
        }
    }

    /**
     * 获取安全API密钥（模拟实现）
     * @param region 区域信息
     * @return 加密后的API密钥
     */
    private String getSecureApiKey(String region) {
        // 实际应从安全存储获取，此处模拟实现
        return String.format("SECURE_KEY_%s_2023", region.toUpperCase());
    }

    /**
     * 解析支付响应
     * @param response 响应实体
     * @return 支付结果
     */
    private PaymentResponse parsePaymentResponse(ResponseEntity<String> response) {
        // 简化实现：实际应使用JSON解析
        if (response.getBody().contains(""success":true")) {
            return new PaymentResponse("SUCCESS", "Payment completed");
        }
        return new PaymentResponse("FAILED", "Payment rejected");
    }

    // 内部类定义
    public static class PaymentRequest {
        private String endpoint;
        private String region;
        private String transactionId;
        private double amount;
        private String currency;
        
        // Getters and setters
        public String getEndpoint() { return endpoint; }
        public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }
        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
        public String getCurrency() { return currency; }
        public void setCurrency(String currency) { this.currency = currency; }
    }

    public static class PaymentResponse {
        private final String status;
        private final String message;
        
        public PaymentResponse(String status, String message) {
            this.status = status;
            this.message = message; }
        
        // Getters
        public String getStatus() { return status; }
        public String getMessage() { return message; }
    }
}

/**
 * 风控验证器
 */
class RiskControlValidator {
    /**
     * 支付请求验证
     * @param request 支付请求
     * @return 验证结果
     */
    public boolean validatePayment(CrossBorderPaymentService.PaymentRequest request) {
        // 实际应包含复杂风控逻辑
        return request != null 
            && request.getAmount() > 0 
            && request.getCurrency() != null
            && request.getEndpoint() != null
            && request.getRegion() != null;
    }
}