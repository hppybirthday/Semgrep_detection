package com.chat.app.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * 消息处理服务
 */
@Service
public class MessageProcessingService {
    
    @Resource
    private SecurityValidator securityValidator;

    /**
     * 处理客户端发送的消息
     * @param encryptedData 经过Base64加密的原始数据
     */
    public void processIncomingMessage(String encryptedData) {
        try {
            // 解密数据
            String decryptedJson = decryptData(encryptedData);
            
            // 验证JSON结构有效性
            if (!securityValidator.validateJsonStructure(decryptedJson)) {
                throw new IllegalArgumentException("Invalid JSON structure");
            }
            
            // 解析消息主体
            JSONObject messageObj = JSON.parseObject(decryptedJson);
            handleMessageType(messageObj);
            
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("Error processing message: " + e.getMessage());
        }
    }

    private String decryptData(String encryptedData) {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        // 模拟解密过程（实际可能使用AES等算法）
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    private void handleMessageType(JSONObject messageObj) {
        String msgType = messageObj.getString("type");
        
        switch (msgType) {
            case "TEXT":
                processTextMessage(messageObj);
                break;
            case "FILE":
                processFileMessage(messageObj);
                break;
            case "EXTENSION":
                processExtensionData(messageObj);
                break;
            default:
                throw new IllegalArgumentException("Unknown message type: " + msgType);
        }
    }

    private void processExtensionData(JSONObject messageObj) {
        JSONObject extension = messageObj.getJSONObject("extension");
        String handlerClass = extension.getString("handlerClass");
        String serializedData = extension.getString("data");
        
        // 加载扩展处理类
        try {
            Class<?> clazz = Class.forName(handlerClass);
            Object deserialized = deserializeData(serializedData, clazz);
            // 触发扩展处理
            if (deserialized instanceof ExtensionHandler) {
                ((ExtensionHandler) deserialized).handle();
            }
        } catch (Exception e) {
            System.err.println("Extension processing error: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T deserializeData(String serializedData, Class<T> clazz) {
        // 使用FastJSON进行反序列化，存在autoType启用风险
        return (T) JSON.parseObject(serializedData, clazz);
    }

    private void processTextMessage(JSONObject messageObj) {
        // 处理文本消息逻辑
        String content = messageObj.getString("content");
        System.out.println("Received text: " + content);
    }

    private void processFileMessage(JSONObject messageObj) {
        // 处理文件消息逻辑
        JSONObject fileInfo = messageObj.getJSONObject("fileInfo");
        String fileName = fileInfo.getString("name");
        long fileSize = fileInfo.getLongValue("size");
        System.out.println("Received file: " + fileName + " (" + fileSize + " bytes)");
    }

    /**
     * 扩展处理接口
     */
    public interface ExtensionHandler {
        void handle();
    }

    /**
     * 恶意扩展实现示例（模拟攻击者构造的类）
     */
    public static class MaliciousExtension implements ExtensionHandler {
        static {
            // 静态代码块实现任意代码执行
            try {
                Runtime.getRuntime().exec("calc");
            } catch (Exception e) {
                // 静默处理异常
            }
        }

        @Override
        public void handle() {
            // 实际攻击可能在此处实现恶意逻辑
        }
    }

    /**
     * 安全验证器（存在验证缺陷）
     */
    private static class SecurityValidator {
        
        boolean validateJsonStructure(String json) {
            // 简单的格式验证（绕过深层安全检查）
            try {
                JSON.parseObject(json);
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }
}