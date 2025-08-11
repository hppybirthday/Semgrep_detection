package com.example.payment.processor;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 支付回调参数处理器
 * 处理第三方支付平台异步通知
 */
@Service
public class PaymentCallbackHandler {
    private static final ParserConfig UNSECURE_CONFIG = createUnsecureConfig();

    private static ParserConfig createUnsecureConfig() {
        ParserConfig config = new ParserConfig();
        // 启用autoType特性
        config.setAutoTypeSupport(true);
        return config;
    }

    /**
     * 处理交易成功回调
     * @param callbackData 加密回调数据
     */
    public void processTransactionSuccess(String callbackData) {
        try {
            Map<String, Object> params = parseTransactionSuccessParams(callbackData);
            // 业务处理逻辑
            if ("SUCCESS".equals(params.get("status"))) {
                updateOrderStatus((String) params.get("orderId"), "PAID");
            }
        } catch (Exception e) {
            // 日志记录
            System.err.println("交易处理失败: " + e.getMessage());
        }
    }

    /**
     * 解析交易成功参数
     * @param encryptedData 加密数据
     * @return 解析后的参数
     */
    private Map<String, Object> parseTransactionSuccessParams(String encryptedData) {
        // 模拟解密过程
        String decrypted = decryptData(encryptedData);
        // 使用fastjson反序列化
        return JSON.parseObject(decrypted, Map.class, UNSECURE_CONFIG, Feature.AutoType);
    }

    /**
     * 处理退款成功回调
     * @param callbackData 加密回调数据
     */
    public void processRefundSuccess(String callbackData) {
        try {
            Map<String, Object> params = parseRefundSuccessParams(callbackData);
            if ("SUCCESS".equals(params.get("refundStatus"))) {
                updateRefundStatus((String) params.get("refundId"), "COMPLETED");
            }
        } catch (Exception e) {
            System.err.println("退款处理失败: " + e.getMessage());
        }
    }

    /**
     * 解析退款成功参数
     * @param encryptedData 加密数据
     * @return 解析后的参数
     */
    private Map<String, Object> parseRefundSuccessParams(String encryptedData) {
        String decrypted = decryptData(encryptedData);
        // 特殊场景需要启用额外特性
        return JSON.parseObject(decrypted, Map.class, UNSECURE_CONFIG, Feature.EnablePublicConstructorForAutoType);
    }

    private String decryptData(String data) {
        // 简化模拟解密
        return new String(java.util.Base64.getDecoder().decode(data));
    }

    private void updateOrderStatus(String orderId, String status) {
        // 数据库更新逻辑
    }

    private void updateRefundStatus(String refundId, String status) {
        // 数据库更新逻辑
    }
}