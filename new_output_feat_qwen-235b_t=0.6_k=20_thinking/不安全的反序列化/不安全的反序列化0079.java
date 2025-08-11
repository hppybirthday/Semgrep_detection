package com.bank.payment.controller;

import com.alibaba.fastjson.JSON;
import com.bank.payment.service.PaymentService;
import com.bank.payment.util.JsonUtils;
import com.bank.payment.vo.PaymentRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * 支付回调处理控制器
 * 处理第三方支付平台回调请求
 */
@RestController
public class PaymentCallbackController {
    
    @Autowired
    private PaymentService paymentService;

    /**
     * 处理支付回调请求
     * @param callbackData JSON格式的回调数据
     * @param request 请求对象
     * @return 处理结果
     */
    @PostMapping("/callback/payment")
    public String handlePaymentCallback(@RequestParam("data") String callbackData, HttpServletRequest request) {
        try {
            // 验证请求来源（示例验证逻辑）
            if (!validateRequestSource(request)) {
                return "INVALID_SOURCE";
            }

            // 将JSON字符串转换为支付请求对象
            PaymentRequest paymentRequest = JsonUtils.convertToObject(callbackData, PaymentRequest.class);
            
            // 处理支付业务逻辑
            boolean result = paymentService.processPayment(paymentRequest);
            
            return result ? "SUCCESS" : "FAILURE";
        } catch (Exception e) {
            // 记录异常日志
            System.err.println("支付回调处理异常: " + e.getMessage());
            return "ERROR";
        }
    }

    /**
     * 验证请求来源是否合法
     */
    private boolean validateRequestSource(HttpServletRequest request) {
        // 实际应验证签名和来源IP
        String sourceIp = request.getRemoteAddr();
        return sourceIp.startsWith("192.168.") || sourceIp.startsWith("10.");
    }
}

package com.bank.payment.util;

import com.alibaba.fastjson.JSON;
import com.bank.payment.vo.PaymentRequest;
import org.springframework.util.StringUtils;

/**
 * JSON处理工具类
 * 提供对象与JSON字符串的转换功能
 */
public class JsonUtils {
    
    /**
     * 将JSON字符串转换为指定类型对象
     * @param json JSON字符串
     * @param clazz 目标类类型
     * @return 转换后的对象
     */
    public static <T> T convertToObject(String json, Class<T> clazz) {
        if (StringUtils.isEmpty(json)) {
            return null;
        }
        
        // 存在漏洞的反序列化操作
        return JSON.parseObject(json, clazz);
    }

    /**
     * 将对象转换为JSON字符串
     */
    public static String convertToJson(Object obj) {
        return JSON.toJSONString(obj);
    }
}

package com.bank.payment.service;

import com.bank.payment.vo.PaymentRequest;
import org.springframework.stereotype.Service;

/**
 * 支付服务类
 * 处理核心支付业务逻辑
 */
@Service
public class PaymentService {
    
    /**
     * 处理支付请求
     * @param request 支付请求数据
     * @return 处理结果
     */
    public boolean processPayment(PaymentRequest request) {
        // 验证请求数据（示例验证逻辑）
        if (request == null || request.getAmount() <= 0) {
            return false;
        }

        // 执行支付逻辑（示例）
        System.out.println("处理支付: " + request.getTransactionId());
        System.out.println("金额: " + request.getAmount());
        
        // 模拟数据库操作
        return savePaymentRecord(request);
    }

    /**
     * 保存支付记录到数据库（模拟）
     */
    private boolean savePaymentRecord(PaymentRequest request) {
        // 实际应包含数据库操作
        System.out.println("保存支付记录: " + request.getTransactionId());
        return true;
    }
}

package com.bank.payment.vo;

import java.math.BigDecimal;

/**
 * 支付请求数据传输对象
 */
public class PaymentRequest {
    private String transactionId;
    private BigDecimal amount;
    private String currency;
    private String payerAccount;
    private String receiverAccount;
    
    // 忽略getter/setter

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public String getPayerAccount() {
        return payerAccount;
    }

    public void setPayerAccount(String payerAccount) {
        this.payerAccount = payerAccount;
    }

    public String getReceiverAccount() {
        return receiverAccount;
    }

    public void setReceiverAccount(String receiverAccount) {
        this.receiverAccount = receiverAccount;
    }
}