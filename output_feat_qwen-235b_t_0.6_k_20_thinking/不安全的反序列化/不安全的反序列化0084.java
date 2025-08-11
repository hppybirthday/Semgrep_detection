package com.example.vulnerableapp.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

// 模拟业务场景：支付回调参数解析
@Controller
@RequestMapping("/payment")
public class PaymentCallbackController {
    
    // 静态初始化块模拟不安全的FastJSON全局配置
    static {
        // 禁用FastJSON内置的autotype安全机制
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    }

    // 模拟交易成功回调
    @RequestMapping("/transaction")
    @ResponseBody
    public Map<String, Object> handleTransaction(@RequestParam String obj) {
        try {
            TransactionResult result = parseTransactionSuccessParams(obj);
            return Map.of("status", "success", "data", result);
        } catch (Exception e) {
            return Map.of("status", "error", "message", e.getMessage());
        }
    }

    // 模拟退款成功回调
    @RequestMapping("/refund")
    @ResponseBody
    public Map<String, Object> handleRefund(@RequestParam String conversationId,
                                            @RequestParam String appId,
                                            @RequestParam String metadata) {
        try {
            // 危险的字符串拼接操作
            String maliciousJson = String.format("{\\"conversationId\\":\\"%s\\",\\"appId\\":\\"%s\\",\\"metadata\\":%s}",
                conversationId, appId, metadata);
            
            RefundResult result = parseRefundSuccessParams(maliciousJson);
            return Map.of("status", "success", "data", result);
        } catch (Exception e) {
            return Map.of("status", "error", "message", e.getMessage());
        }
    }

    // 存在漏洞的反序列化方法 - 交易参数解析
    private TransactionResult parseTransactionSuccessParams(String json) {
        // 直接反序列化不可信输入，未进行类型白名单校验
        return JSON.parseObject(json, TransactionResult.class);
    }

    // 存在漏洞的反序列化方法 - 退款参数解析
    private RefundResult parseRefundSuccessParams(String json) {
        // 使用不安全的默认解析配置
        return JSON.parseObject(json, RefundResult.class);
    }

    // 数据模型类 - 交易结果
    static class TransactionResult {
        private String transactionId;
        private Double amount;
        private UserInfo user;
        // getters/setters
        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
        public Double getAmount() { return amount; }
        public void setAmount(Double amount) { this.amount = amount; }
        public UserInfo getUser() { return user; }
        public void setUser(UserInfo user) { this.user = user; }
    }

    // 数据模型类 - 退款结果
    static class RefundResult {
        private String refundId;
        private TransactionResult originalTransaction;
        // getters/setters
        public String getRefundId() { return refundId; }
        public void setRefundId(String refundId) { this.refundId = refundId; }
        public TransactionResult getOriginalTransaction() { return originalTransaction; }
        public void setOriginalTransaction(TransactionResult originalTransaction) {
            this.originalTransaction = originalTransaction;
        }
    }

    // 嵌套数据模型
    static class UserInfo {
        private String username;
        private String roles;
        // getters/setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getRoles() { return roles; }
        public void setRoles(String roles) { this.roles = roles; }
    }
}