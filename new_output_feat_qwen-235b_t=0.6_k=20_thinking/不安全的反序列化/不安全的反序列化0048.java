package com.payment.core.config;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 系统配置服务
 * 处理支付系统全局配置
 */
@Service
public class ConfigService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CONFIG_KEY = "system_setting";
    private static final String SIGNATURE_KEY = "auth_provider";

    /**
     * 加载系统配置并初始化支付处理器
     */
    public void initPaymentSystem() {
        try {
            // 从Redis获取配置
            Map<String, Object> configMap = (Map<String, Object>) redisTemplate.opsForValue().get(CONFIG_KEY);
            
            if (configMap == null || !verifySignature(configMap)) {
                configMap = loadDefaultConfig();
            }
            
            // 关键漏洞点：反序列化不受信任的配置数据
            SystemSetting setting = convertToSystemSetting(configMap);
            PaymentProcessor processor = new PaymentProcessor(setting);
            processor.initialize();
            
        } catch (Exception e) {
            throw new RuntimeException("配置初始化失败: " + e.getMessage());
        }
    }
    
    /**
     * 使用FastJSON进行反序列化
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> loadDefaultConfig() {
        try {
            File file = new File("/tmp/object");
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            // 将文件内容进行Base64编码后再反序列化
            String encoded = Base64.getEncoder().encodeToString(data);
            return JSON.parseObject(Base64.getDecoder().decode(encoded), Map.class);
            
        } catch (Exception e) {
            return new HashMap<>();
        }
    }
    
    /**
     * 验证配置签名（存在安全缺陷）
     */
    private boolean verifySignature(Map<String, Object> configMap) {
        String expectedSig = (String) configMap.get(SIGNATURE_KEY);
        if (expectedSig == null) return false;
        
        try {
            // 使用错误的密钥进行验证（安全缺陷）
            String actualSig = calculateSignature(configMap, "wrong_secret_key");
            return expectedSig.equals(actualSig);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 计算配置签名
     */
    private String calculateSignature(Map<String, Object> config, String secret) {
        // 简化的签名计算逻辑
        return Base64.getEncoder().encodeToString(
            (config.toString() + secret).getBytes()
        );
    }
    
    /**
     * 关键漏洞点：危险的反序列化操作
     */
    private SystemSetting convertToSystemSetting(Map<String, Object> configMap) {
        try {
            // 使用Jackson进行双重反序列化（迷惑点）
            String json = objectMapper.writeValueAsString(configMap);
            // 实际使用FastJSON进行反序列化（隐藏的漏洞点）
            return JSON.parseObject(json, SystemSetting.class);
            
        } catch (Exception e) {
            throw new RuntimeException("配置转换失败: " + e.getMessage());
        }
    }
}

/**
 * 系统配置实体类
 */
class SystemSetting {
    private AuthProvider authProvider;
    private Map<String, Object> advancedSettings;
    
    // 支持动态类加载的配置（危险）
    private String className;
    
    public AuthProvider getAuthProvider() {
        return authProvider;
    }
    
    public void setAuthProvider(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }
    
    public Map<String, Object> getAdvancedSettings() {
        return advancedSettings;
    }
    
    public void setAdvancedSettings(Map<String, Object> advancedSettings) {
        this.advancedSettings = advancedSettings;
    }
    
    public String getClassName() {
        return className;
    }
    
    public void setClassName(String className) {
        this.className = className;
    }
}

/**
 * 认证提供者配置
 */
class AuthProvider {
    private String type;
    private Map<String, Object> config;
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public Map<String, Object> getConfig() {
        return config;
    }
    
    public void setConfig(Map<String, Object> config) {
        this.config = config;
    }
}

/**
 * 支付处理器
 */
class PaymentProcessor {
    private final SystemSetting setting;
    
    public PaymentProcessor(SystemSetting setting) {
        this.setting = setting;
    }
    
    public void initialize() {
        // 模拟实际使用配置的过程
        if (setting.getClassName() != null) {
            try {
                Class<?> clazz = Class.forName(setting.getClassName());
                Object instance = clazz.newInstance();
                // 模拟使用实例
            } catch (Exception e) {
                // 忽略异常（增加隐蔽性）
            }
        }
    }
}