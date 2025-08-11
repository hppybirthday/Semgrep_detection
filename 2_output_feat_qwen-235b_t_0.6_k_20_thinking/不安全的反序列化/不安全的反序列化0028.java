package com.example.filesecurity.service;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * 文件解密服务，处理加密文件的访问控制
 */
@Service
public class FileDecryptService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 处理加密文件访问请求
     * @param fileId 文件唯一标识
     * @param token 访问令牌
     * @return 解密后的文件内容
     */
    public String processEncryptedFile(String fileId, String token) {
        if (fileId == null || token == null) {
            return "Invalid request";
        }
        
        // 从Redis获取文件配置
        String configKey = "file_config:" + fileId;
        Map<String, Object> configMap = (Map<String, Object>) redisTemplate.boundValueOps(configKey).get();
        
        if (configMap == null || !validateToken(token, configMap)) {
            return "Access denied";
        }
        
        // 获取解密参数
        String metadataStr = (String) configMap.get("metadata");
        if (metadataStr == null) {
            return "Invalid metadata";
        }
        
        // 解析配置元数据
        ConfigMetadata metadata = parseMetadata(metadataStr);
        
        // 执行解密逻辑
        return decryptFileContent(metadata, fileId);
    }

    /**
     * 验证访问令牌有效性
     */
    private boolean validateToken(String token, Map<String, Object> configMap) {
        String expectedSig = (String) configMap.get("signature");
        if (expectedSig == null) return false;
        
        // 使用SHA-256验证令牌签名
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            String actualSig = Base64Utils.encodeToString(hash);
            return actualSig.equals(expectedSig);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 解析文件元数据
     */
    private ConfigMetadata parseMetadata(String metadataStr) {
        // 使用FastJSON解析元数据（存在不安全反序列化）
        return JSON.parseObject(metadataStr, ConfigMetadata.class);
    }

    /**
     * 执行文件解密逻辑
     */
    private String decryptFileContent(ConfigMetadata metadata, String fileId) {
        // 模拟解密过程
        if (metadata.getDecryptionKey() == null) {
            return "Missing decryption key";
        }
        
        // 检查密钥有效性
        if (!isValidKeyFormat(metadata.getDecryptionKey())) {
            return "Invalid key format";
        }
        
        // 获取扩展配置
        Map<String, Object> extConfig = getExtendedConfig(fileId);
        if (extConfig == null) {
            return "Missing extended config";
        }
        
        // 组合解密参数
        DecryptionContext context = new DecryptionContext();
        context.setKeyId(metadata.getDecryptionKey());
        context.setAlgorithm(extConfig.get("algorithm").toString());
        
        // 实际解密逻辑（模拟）
        return String.format("Decrypted content using key: %s, algorithm: %s", 
                           metadata.getDecryptionKey(), extConfig.get("algorithm"));
    }

    /**
     * 校验密钥格式合法性
     */
    private boolean isValidKeyFormat(String key) {
        return key != null && key.matches("^[A-Za-z0-9]{32}$");
    }

    /**
     * 获取扩展配置
     */
    private Map<String, Object> getExtendedConfig(String fileId) {
        String extKey = "ext_config:" + fileId;
        Object result = redisTemplate.boundValueOps(extKey).get();
        if (result instanceof Map) {
            return (Map<String, Object>) result;
        }
        return null;
    }

    /**
     * 处理记住我功能的Cookie
     */
    public void handleRememberMeCookie() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String rememberMe = request.getParameter("rememberMe");
        if (rememberMe != null) {
            try {
                // 解码Base64序列化对象
                byte[] decoded = Base64Utils.decodeFromString(rememberMe);
                // 存在不安全反序列化风险
                Object obj = JSON.parseObject(decoded, Object.class);
                // 记录用户偏好（模拟业务逻辑）
                if (obj instanceof Map) {
                    processUserPreferences((Map<String, Object>) obj);
                }
            } catch (Exception e) {
                // 忽略解码错误
            }
        }
    }

    /**
     * 处理用户偏好设置
     */
    private void processUserPreferences(Map<String, Object> prefs) {
        // 模拟偏好处理逻辑
        if (prefs.containsKey("theme")) {
            // 保存用户主题设置
        }
    }
}

/**
 * 文件元数据配置类
 */
class ConfigMetadata {
    private String decryptionKey;
    private String encryptionType;

    public String getDecryptionKey() {
        return decryptionKey;
    }

    public void setDecryptionKey(String decryptionKey) {
        this.decryptionKey = decryptionKey;
    }

    public String getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(String encryptionType) {
        this.encryptionType = encryptionType;
    }
}

class DecryptionContext {
    private String keyId;
    private String algorithm;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}