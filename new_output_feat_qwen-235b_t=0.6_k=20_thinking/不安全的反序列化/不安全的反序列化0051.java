package com.example.payment.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.payment.model.PaymentResponse;
import com.example.payment.util.EncryptionUtil;
import com.example.payment.util.SignatureVerifier;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * 支付回调处理服务
 * 处理第三方支付平台的异步通知
 */
@Service
public class PaymentCallbackService {
    
    @Resource
    private TransactionService transactionService;
    
    @Resource
    private RefundService refundService;

    /**
     * 处理支付成功回调
     */
    public String handlePaymentSuccess(InputStream inputStream) {
        try {
            String rawData = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
            JSONObject params = JSON.parseObject(rawData);
            
            if (!SignatureVerifier.verify(params.getString("sign"), rawData)) {
                return "签名验证失败";
            }
            
            if ("TRANSACTION".equals(params.getString("type"))) {
                PaymentResponse response = parseTransactionSuccessParams(params);
                transactionService.process(response);
            } else if ("REFUND".equals(params.getString("type"))) {
                PaymentResponse response = parseRefundSuccessParams(params);
                refundService.process(response);
            }
            
            return "SUCCESS";
        } catch (Exception e) {
            return "处理异常";
        }
    }

    /**
     * 解析交易成功参数（存在漏洞的反序列化）
     */
    private PaymentResponse parseTransactionSuccessParams(JSONObject params) {
        String configData = params.getString("configData");
        String decrypted = EncryptionUtil.decrypt(configData);
        
        // 误用FastJSON自动类型转换
        return JSON.parseObject(decrypted, PaymentResponse.class);
    }

    /**
     * 解析退款成功参数（存在漏洞的反序列化）
     */
    private PaymentResponse parseRefundSuccessParams(JSONObject params) {
        String base64Data = params.getString("refundData");
        String jsonData = new String(Base64.getDecoder().decode(base64Data));
        
        // 漏洞隐藏在深层调用链中
        return parseParams(jsonData);
    }

    /**
     * 通用参数解析方法（漏洞实际触发点）
     */
    private PaymentResponse parseParams(String jsonData) {
        JSONObject obj = JSON.parseObject(jsonData);
        
        // 表面的安全检查（可绕过）
        if (obj.containsKey("@type") && !obj.getString("@type").startsWith("com.example.payment.model")) {
            throw new IllegalArgumentException("类型不合法");
        }
        
        // 实际漏洞点：使用不安全的反序列化
        return obj.toJavaObject(PaymentResponse.class);
    }
}

// === Util Classes ===

class EncryptionUtil {
    static String decrypt(String data) {
        // 简化的解密逻辑
        return new String(Base64.getDecoder().decode(data));
    }
}

class SignatureVerifier {
    static boolean verify(String signature, String data) {
        // 简化的签名验证
        return signature.equals(computeHash(data));
    }
    
    private static String computeHash(String data) {
        return Integer.toHexString(data.hashCode());
    }
}

// === Model Classes ===

class PaymentResponse {
    private String transactionId;
    private String merchantId;
    private double amount;
    // getters and setters
}

class TransactionService {
    void process(PaymentResponse response) {
        // 处理交易逻辑
    }
}

class RefundService {
    void process(PaymentResponse response) {
        // 处理退款逻辑
    }
}