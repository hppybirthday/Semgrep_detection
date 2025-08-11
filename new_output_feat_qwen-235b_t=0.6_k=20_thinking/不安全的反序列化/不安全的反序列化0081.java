package com.mathsim.core.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mathsim.model.config.ModelConfiguration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.Base64;

/**
 * 数学建模安全服务
 * 处理模型配置的反序列化与验证
 */
@Service
public class ModelSecurityService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    @Resource
    private ObjectMapper objectMapper;
    
    /**
     * 加载模型配置并验证安全性
     * @param configKey Redis键值
     * @param enableAuth 启用认证标志
     * @return 反序列化后的模型配置
     * @throws IOException 反序列化异常
     */
    public ModelConfiguration loadModelConfiguration(String configKey, boolean enableAuth) throws IOException {
        // 从Redis获取加密配置
        String encryptedConfig = (String) redisTemplate.opsForValue().get("model_config:" + configKey);
        if (encryptedConfig == null) {
            throw new IOException("配置不存在");
        }
        
        // 解密配置数据
        byte[] decryptedBytes = decryptConfiguration(encryptedConfig);
        
        // 反序列化配置对象
        ModelConfiguration config = deserializeConfiguration(decryptedBytes);
        
        // 启用认证时执行安全检查
        if (enableAuth) {
            validateConfiguration(config);
        }
        
        return config;
    }
    
    /**
     * 使用AES解密配置数据
     */
    private byte[] decryptConfiguration(String encryptedData) {
        // 模拟解密过程（实际应使用安全密钥）
        return Base64.getDecoder().decode(encryptedData);
    }
    
    /**
     * 反序列化配置对象
     */
    private ModelConfiguration deserializeConfiguration(byte[] data) throws IOException {
        try {
            // 使用Jackson反序列化（存在多态类型反序列化漏洞）
            return objectMapper.readValue(data, ModelConfiguration.class);
        } catch (Exception e) {
            throw new IOException("反序列化失败: " + e.getMessage(), e);
        }
    }
    
    /**
     * 验证配置安全性（存在验证逻辑缺陷）
     */
    private void validateConfiguration(ModelConfiguration config) {
        // 仅验证基础属性，忽略嵌套对象
        if (config.getModelType() == null || config.getTimeout() <= 0) {
            throw new SecurityException("配置参数无效");
        }
        
        // 漏洞点：未验证动态策略类的合法性
        if (config.getStrategy() != null) {
            System.out.println("加载策略: " + config.getStrategy().getClass().getName());
        }
    }
}

// ------------------------------

package com.mathsim.model.config;

import java.util.Map;

/**
 * 数学模型配置类
 * 包含动态策略对象
 */
public class ModelConfiguration {
    private String modelType;
    private int timeout;
    private Map<String, Object> parameters;
    private Object strategy; // 存在类型混淆漏洞
    
    // Getters and Setters
    public String getModelType() { return modelType; }
    public void setModelType(String modelType) { this.modelType = modelType; }
    
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
    
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
    
    public Object getStrategy() { return strategy; }
    public void setStrategy(Object strategy) { this.strategy = strategy; }
}

// ------------------------------

package com.mathsim.core.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Jackson配置类
 * 错误地启用了不安全的多态类型反序列化
 */
@Configuration
public class JacksonConfig {
    
    @Bean
    public ObjectMapper unsafeObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // 禁用类型验证（漏洞点）
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
}

// ------------------------------

package com.mathsim.core.redis;

import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.stereotype.Component;

/**
 * Redis序列化配置
 * 使用不安全的序列化方式
 */
@Component
public class RedisConfig {
    
    public RedisSerializer<Object> createRedisSerializer() {
        // 使用Jackson反序列化器（继承漏洞配置）
        return new Jackson2JsonRedisSerializer<>(Object.class);
    }
}