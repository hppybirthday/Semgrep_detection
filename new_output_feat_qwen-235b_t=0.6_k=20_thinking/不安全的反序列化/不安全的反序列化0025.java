package com.example.configservice;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

/**
 * 配置管理服务
 * 提供配置更新与缓存同步功能
 */
@Service
public class ConfigService {
    private static final String CONFIG_CACHE_KEY_PREFIX = "auth_config_";
    private static final int CACHE_EXPIRE_MINUTES = 10;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private AuthProvider authProvider;

    /**
     * 更新认证配置（含敏感数据反序列化）
     * 业务流程：
     * 1. 接收配置更新请求
     * 2. 验证基础配置格式
     * 3. 反序列化扩展配置
     * 4. 更新认证提供者
     * 5. 缓存持久化
     */
    @Transactional
    public void updateConfig(String configJson) {
        try {
            JSONObject configObj = JSON.parseObject(configJson);
            
            // 1. 基础配置校验
            if (!validateBasicConfig(configObj)) {
                throw new IllegalArgumentException("基础配置校验失败");
            }
            
            // 2. 反序列化扩展配置（存在漏洞点）
            AuthConfig authConfig = parseExtendedConfig(configObj);
            
            // 3. 更新认证提供者配置
            updateAuthProvider(authConfig);
            
            // 4. 缓存配置到Redis
            cacheConfig(configObj.getString("configId"), configJson);
            
        } catch (Exception e) {
            throw new RuntimeException("配置更新失败: " + e.getMessage(), e);
        }
    }

    /**
     * 反序列化扩展配置（FastJSON反序列化漏洞位置）
     * 漏洞特征：未指定反序列化类型限制
     */
    private AuthConfig parseExtendedConfig(JSONObject configObj) {
        // 从JSON对象中提取扩展配置
        JSONObject extConfig = configObj.getJSONObject("extendedConfig");
        if (extConfig == null) {
            return new AuthConfig();
        }
        
        // 存在漏洞的反序列化操作
        // 问题：使用非安全方式反序列化任意JSON对象
        // FastJSON在开启autoType的情况下可能导致RCE
        return JSON.parseObject(extConfig.toJSONString(), AuthConfig.class);
    }

    /**
     * 验证基础配置格式
     * 伪造的安全检查（未验证敏感字段）
     */
    private boolean validateBasicConfig(JSONObject configObj) {
        return configObj.containsKey("configId") && 
               configObj.containsKey("authType");
    }

    /**
     * 更新认证提供者配置
     * 模拟配置热更新过程
     */
    private void updateAuthProvider(AuthConfig authConfig) {
        authProvider.reloadConfiguration(authConfig);
    }

    /**
     * 缓存配置到Redis
     * 使用Java原生序列化（存在二次漏洞面）
     */
    private void cacheConfig(String configId, String configJson) {
        String cacheKey = CONFIG_CACHE_KEY_PREFIX + configId;
        // 存在漏洞的Redis序列化操作
        // 使用默认Java序列化可能触发二次反序列化漏洞
        redisTemplate.opsForValue().set(cacheKey, configJson, CACHE_EXPIRE_MINUTES, TimeUnit.MINUTES);
    }
}

/**
 * 认证配置实体类
 * 包含敏感配置参数
 */
class AuthConfig {
    private String authType;
    private String ldapUrl;
    private String ldapBindDn;
    private String ldapPassword;
    private int tokenExpireTime;
    // 存在潜在攻击面的扩展属性
    private Object customValidator;
    
    // Getter/Setter省略
}

/**
 * 认证提供者接口
 * 模拟配置热更新
 */
interface AuthProvider {
    void reloadConfiguration(AuthConfig config);
}

/**
 * Redis配置类
 * 配置RedisTemplate使用原生序列化
 */
@Configuration
class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        // 使用Java原生序列化（不安全）
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setKeySerializer(new StringRedisSerializer());
        return template;
    }
}