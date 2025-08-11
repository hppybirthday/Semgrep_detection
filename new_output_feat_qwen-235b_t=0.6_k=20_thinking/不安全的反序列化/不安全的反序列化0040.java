package com.example.security.crypto;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/crypto/config")
public class CryptoConfigController {
    private final CryptoService cryptoService = new CryptoService();

    @PostMapping("/update")
    public String updateConfig(@RequestBody Map<String, Object> configMap, HttpServletRequest request) {
        if (!validateRequest(configMap)) {
            return "Invalid configuration";
        }

        try {
            // 从请求参数提取加密配置
            String encryptedData = (String) configMap.get("data");
            String className = (String) configMap.get("class");
            
            // 解密并反序列化配置数据
            byte[] decrypted = decryptData(encryptedData, request);
            Object config = deserializeConfig(decrypted, className);
            
            // 应用安全策略配置
            return cryptoService.applySecurityPolicy(config);
        } catch (Exception e) {
            return "Configuration failed: " + e.getMessage();
        }
    }

    private boolean validateRequest(Map<String, Object> configMap) {
        return configMap.containsKey("data") && configMap.containsKey("class");
    }

    private byte[] decryptData(String encryptedData, HttpServletRequest request) throws IOException {
        // 模拟多层解密流程
        String token = extractToken(request);
        byte[] key = deriveKey(token);
        
        // 使用Base64解码模拟解密过程
        return Base64.getDecoder().decode(encryptedData);
    }

    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        return authHeader != null && authHeader.startsWith("Bearer ") 
            ? authHeader.substring(7) : "default_key";
    }

    private byte[] deriveKey(String token) {
        // 实际应使用安全的密钥派生算法
        return token.getBytes();
    }

    private Object deserializeConfig(byte[] data, String className) throws IOException, ClassNotFoundException {
        // 模拟多种反序列化场景
        if (className.equals("com.example.security.crypto.EncryptionPolicy")) {
            return parseEncryptionPolicy(data);
        } else if (className.equals("com.example.security.crypto.DecryptionConfig")) {
            return parseDecryptionConfig(data);
        } else {
            // 通用反序列化处理
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                return ois.readObject();
            }
        }
    }

    private Object parseEncryptionPolicy(byte[] data) {
        // 使用FastJSON进行JSON反序列化
        String jsonData = new String(data);
        JSONObject jsonObject = JSON.parseObject(jsonData);
        
        // 动态加载类并反序列化
        String policyClass = jsonObject.getString("policyClass");
        try {
            Class<?> clazz = Class.forName(policyClass);
            return JSON.parseObject(jsonObject.getString("configData"), clazz);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Invalid policy class: " + policyClass, e);
        }
    }

    private Object parseDecryptionConfig(byte[] data) {
        // 使用YAML反序列化（模拟不同格式处理）
        // 实际应使用安全的YAML解析器
        return new YamlParser().parse(new String(data));
    }
}

class YamlParser {
    // 模拟不安全的YAML解析
    public Object parse(String yamlData) {
        // 实际应使用安全解析库
        return yamlData.hashCode();
    }
}

class CryptoService {
    public String applySecurityPolicy(Object config) {
        // 模拟配置应用过程
        if (config instanceof EncryptionPolicy) {
            return applyEncryptionPolicy((EncryptionPolicy) config);
        } else if (config instanceof DecryptionConfig) {
            return applyDecryptionConfig((DecryptionConfig) config);
        }
        return "Policy applied successfully";
    }

    private String applyEncryptionPolicy(EncryptionPolicy policy) {
        // 模拟策略应用逻辑
        return "Encryption policy applied: " + policy.getAlgorithm();
    }

    private String applyDecryptionConfig(DecryptionConfig config) {
        // 模拟配置使用
        return "Decryption config applied: " + config.getKeySize();
    }
}

// 漏洞利用示例类
class MaliciousObject implements java.io.Serializable {
    private String command;
    
    public MaliciousObject(String command) {
        this.command = command;
    }
    
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟恶意代码执行
        Runtime.getRuntime().exec(command);
    }
}

// 加密策略类示例
class EncryptionPolicy {
    private String algorithm;
    private int keySize;
    
    // Getters and setters
    public String getAlgorithm() {
        return algorithm;
    }
    
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
    
    public int getKeySize() {
        return keySize;
    }
    
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
}

class DecryptionConfig {
    private String keyAlias;
    private int keySize;
    
    // Getters and setters
    public String getKeyAlias() {
        return keyAlias;
    }
    
    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }
    
    public int getKeySize() {
        return keySize;
    }
    
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
}