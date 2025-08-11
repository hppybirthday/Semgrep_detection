package com.example.bank.payment;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;

/**
 * 支付回调处理器 - 存在SSRF漏洞示例
 */
@Component
public class PaymentCallbackHandler {
    
    @Autowired
    private PaymentService paymentService;

    @Transactional
    public void processPaymentCallback(String callbackUrl, String transactionId) {
        // 模拟处理支付回调
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // 漏洞点：直接使用用户传入的callbackUrl
            HttpGet request = new HttpGet(callbackUrl);
            request.addHeader("X-Transaction-ID", transactionId);
            
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                
                if (response.getStatusLine().getStatusCode() == 200) {
                    // 更新支付状态
                    paymentService.updatePaymentStatus(transactionId, "PAID");
                    logSuccess(callbackUrl, responseBody);
                } else {
                    handlePaymentFailure(transactionId, responseBody);
                }
            }
            
        } catch (IOException e) {
            handlePaymentFailure(transactionId, "HTTP Error: " + e.getMessage());
        }
    }

    private void logSuccess(String callbackUrl, String responseBody) {
        // 记录成功回调日志
        System.out.println("Callback successful to " + callbackUrl);
        System.out.println("Response: " + responseBody);
    }

    private void handlePaymentFailure(String transactionId, String errorMessage) {
        // 处理支付失败逻辑
        System.err.println("Payment failed for transaction " + transactionId);
        System.err.println("Error: " + errorMessage);
        
        // 更新支付状态为失败
        paymentService.updatePaymentStatus(transactionId, "FAILED");
    }

    // 模拟的服务依赖
    static class PaymentService {
        public void updatePaymentStatus(String transactionId, String status) {
            System.out.println("Updating transaction " + transactionId + " to status " + status);
        }
    }

    // 测试入口
    public static void main(String[] args) {
        PaymentCallbackHandler handler = new PaymentCallbackHandler();
        handler.paymentService = new PaymentService();
        
        // 恶意示例：攻击者控制的callbackUrl
        String maliciousUrl = "http://localhost:8080/internal-api/transfer?amount=1000000&to=hacker_account";
        handler.processPaymentCallback(maliciousUrl, "TXN123456789");
    }
}