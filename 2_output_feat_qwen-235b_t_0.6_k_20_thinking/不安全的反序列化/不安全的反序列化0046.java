package com.example.payment.service;

import com.alibaba.fastjson.JSON;
import com.example.payment.dto.PaymentConfig;
import com.example.payment.util.DataValidator;
import com.example.payment.util.EncryptionUtil;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 支付配置处理服务
 * 处理用户提交的加密支付配置数据
 */
@Service
public class PaymentConfigProcessor {
    
    @Resource
    private DataValidator dataValidator;
    
    @Resource
    private EncryptionUtil encryptionUtil;
    
    /**
     * 处理支付数据配置
     * @param encryptedData 加密的配置数据
     * @return 处理后的配置对象
     * @throws Exception 处理异常
     */
    public PaymentConfig processPaymentData(String encryptedData) throws Exception {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new IllegalArgumentException("加密数据不能为空");
        }
        
        String decryptedData = encryptionUtil.decrypt(encryptedData);
        if (!dataValidator.validateDataFormat(decryptedData)) {
            throw new IllegalArgumentException("数据格式校验失败");
        }
        
        return convertPaymentData(decryptedData);
    }
    
    private PaymentConfig convertPaymentData(String jsonData) {
        // 解析JSON配置数据
        return JSON.parseObject(jsonData, PaymentConfig.class);
    }
    
    /**
     * 批量处理支付配置列表
     * @param encryptedList 加密的配置列表
     * @return 处理后的配置列表
     */
    public List<PaymentConfig> batchProcess(List<String> encryptedList) {
        return encryptedList.stream()
            .filter(dataValidator::validateDataLength)
            .map(encrypted -> {
                String decrypted = encryptionUtil.decrypt(encrypted);
                return convertPaymentData(decrypted);
            })
            .toList();
    }
}