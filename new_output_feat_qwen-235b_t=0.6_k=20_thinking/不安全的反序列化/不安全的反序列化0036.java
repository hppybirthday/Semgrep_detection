package com.crm.feedback.controller;

import com.crm.feedback.service.FeedbackService;
import com.crm.feedback.dto.FeedbackRequest;
import com.crm.feedback.util.DataProcessor;
import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/feedback")
public class FeedbackController {
    @Autowired
    private FeedbackService feedbackService;

    /**
     * 处理客户反馈提交
     * @param request HTTP请求对象
     * @param encryptedData 经过AES加密的反馈数据
     * @return 处理结果
     */
    @PostMapping("/submit")
    public String submitFeedback(HttpServletRequest request, @RequestParam String encryptedData) {
        try {
            // 验证请求来源IP
            if (!DataProcessor.validateClientIP(request.getRemoteAddr())) {
                return "Access Denied";
            }

            // 解密并处理反馈数据
            Map<String, Object> feedbackData = feedbackService.processEncryptedFeedback(encryptedData);
            
            // 记录审计日志
            DataProcessor.logAudit(request, feedbackData);
            
            return "Feedback received successfully";
        } catch (Exception e) {
            // 记录异常信息
            DataProcessor.logError("Feedback submission failed: " + e.getMessage());
            return "Internal Server Error";
        }
    }
}

package com.crm.feedback.service;

import com.crm.feedback.dto.Feedback;
import com.crm.feedback.util.DataProcessor;
import com.alibaba.fastjson.JSON;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class FeedbackService {
    /**
     * 处理加密的反馈数据
     * @param encryptedData 加密的反馈数据
     * @return 解析后的数据映射
     */
    public Map<String, Object> processEncryptedFeedback(String encryptedData) throws Exception {
        // 使用硬编码密钥解密数据（存在安全风险）
        String decryptedData = DataProcessor.decryptAES(encryptedData, "crm_feedback_key");
        
        // 反序列化JSON数据（存在不安全反序列化漏洞）
        return JSON.parseObject(decryptedData, Map.class);
    }

    /**
     * 存储反馈记录
     * @param feedback 反馈对象
     */
    public void storeFeedback(Feedback feedback) {
        // 模拟数据库存储操作
        DataProcessor.saveToDatabase(feedback);
    }
}

package com.crm.feedback.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

public class DataProcessor {
    /**
     * AES解密实现
     * @param encryptedData 加密数据
     * @param key 解密密钥
     * @return 解密后的明文
     */
    public static String decryptAES(String encryptedData, String key) throws Exception {
        if (StringUtils.isEmpty(encryptedData) || StringUtils.isEmpty(key)) {
            throw new IllegalArgumentException("Invalid input parameters");
        }

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    /**
     * 验证客户端IP地址
     * @param clientIP 客户端IP
     * @return 验证结果
     */
    public static boolean validateClientIP(String clientIP) {
        // 模拟IP白名单验证
        return clientIP != null && (clientIP.equals("192.168.1.100") || clientIP.startsWith("10.0.0."));
    }

    /**
     * 记录审计日志
     * @param request HTTP请求
     * @param data 反馈数据
     */
    public static void logAudit(HttpServletRequest request, Map<String, Object> data) {
        // 模拟日志记录操作
        System.out.println("[" + request.getRemoteAddr() + "] Feedback received: " + data.toString());
    }

    /**
     * 错误日志记录
     * @param message 错误信息
     */
    public static void logError(String message) {
        // 模拟错误日志记录
        System.err.println("[ERROR] " + message);
    }

    /**
     * 模拟数据库存储操作
     * @param feedback 反馈对象
     */
    public static void saveToDatabase(Object feedback) {
        // 模拟持久化操作
        System.out.println("Storing feedback: " + feedback.toString());
    }
}

package com.crm.feedback.dto;

import com.alibaba.fastjson.annotation.JSONField;

import java.util.Date;

/**
 * 客户反馈数据传输对象
 */
public class Feedback {
    @JSONField(name = "content")
    private String content;
    
    @JSONField(name = "userId")
    private Long userId;
    
    @JSONField(name = "timestamp")
    private Date timestamp;
    
    @JSONField(name = "attachments")
    private String[] attachments;

    // Getters and setters
    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public String[] getAttachments() {
        return attachments;
    }

    public void setAttachments(String[] attachments) {
        this.attachments = attachments;
    }
}