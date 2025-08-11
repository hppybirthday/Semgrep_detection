package com.bank.payment.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * 支付回调服务 - 存在SSRF漏洞
 */
@Service
public class PaymentCallbackService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    // 模拟银行内部API访问
    private static final String INTERNAL_API_PREFIX = "http://internal-bank-api";
    
    /**
     * 处理支付结果回调
     * @param callbackUrl 外部商户提供的回调地址
     * @param paymentId 支付流水号
     * @param status 支付状态
     * @return
     */
    public boolean handlePaymentCallback(String callbackUrl, String paymentId, String status) {
        try {
            // 构造回调参数
            Map<String, String> params = new HashMap<>();
            params.put("paymentId", paymentId);
            params.put("status", status);
            
            // 漏洞点：直接使用用户输入的URL进行请求
            URI uri = UriComponentsBuilder.fromHttpUrl(callbackUrl)
                .queryParam("paymentId", paymentId)
                .queryParam("status", status)
                .build().toUri();
            
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            
            // 记录回调结果
            logCallbackResult(callbackUrl, response.getStatusCodeValue(), response.getBody());
            
            return response.getStatusCodeValue() == 200;
        } catch (Exception e) {
            logCallbackResult(callbackUrl, 500, e.getMessage());
            return false;
        }
    }
    
    /**
     * 记录回调日志（包含敏感信息）
     */
    private void logCallbackResult(String url, int status, String response) {
        System.out.println(String.format("回调地址: %s, 状态码: %d, 响应: %s", url, status, response));
        // 实际系统中会记录到审计日志
    }
    
    /**
     * 定时任务同步内部账户（演示SSRF危害）
     */
    public void syncInternalAccount() {
        // 正常内部调用（安全）
        String internalUrl = INTERNAL_API_PREFIX + "/account/sync?accountId=12345";
        ResponseEntity<String> response = restTemplate.getForEntity(internalUrl, String.class);
        System.out.println("内部账户同步结果: " + response.getBody());
    }
}

/**
 * 控制器层示例
 */
@RestController
class PaymentController {
    
    @Autowired
    private PaymentCallbackService callbackService;
    
    // 模拟外部回调接口
    @GetMapping("/payment/callback")
    public String externalCallback(
            @RequestParam String callbackUrl,
            @RequestParam String paymentId,
            @RequestParam String status) {
        
        boolean success = callbackService.handlePaymentCallback(callbackUrl, paymentId, status);
        return success ? "Callback Success" : "Callback Failed";
    }
    
    // 模拟内部定时任务接口
    @GetMapping("/admin/sync/account")
    public String internalSync() {
        callbackService.syncInternalAccount();
        return "Account Sync Triggered";
    }
}

/**
 * 配置类（简化版）
 */
@Configuration
class AppConfig {
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}