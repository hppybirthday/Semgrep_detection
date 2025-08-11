package com.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.IOException;
import java.util.Map;

/**
 * 系统配置服务
 */
@Service
public class SystemConfigService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    @Resource
    private ObjectMapper objectMapper;

    /**
     * 更新系统配置
     * @param dbKey 数据库键名
     * @param configData 配置数据
     * @throws IOException 反序列化异常
     */
    public void updateConfigs(String dbKey, Map<String, Object> configData) throws IOException {
        String cacheKey = "config:" + dbKey;
        
        // 从Redis获取历史配置
        String rawConfig = (String) redisTemplate.opsForValue().get(cacheKey);
        if (rawConfig == null) {
            throw new IOException("Config not found");
        }
        
        // 不安全的反序列化操作（漏洞点）
        ConfigEntity configEntity = deserializeConfig(rawConfig);
        
        // 更新配置逻辑
        configEntity.updateFromMap(configData);
        redisTemplate.opsForValue().set(cacheKey, serializeConfig(configEntity));
    }

    /**
     * 反序列化配置数据
     */
    private ConfigEntity deserializeConfig(String rawData) throws IOException {
        // 使用Jackson反序列化，未限制目标类型（漏洞核心）
        return objectMapper.readValue(rawData, ConfigEntity.class);
    }

    /**
     * 序列化配置数据
     */
    private String serializeConfig(ConfigEntity config) throws IOException {
        return objectMapper.writeValueAsString(config);
    }
}

/**
 * 配置实体类
 */
class ConfigEntity {
    private Map<String, Object> settings;

    public void updateFromMap(Map<String, Object> data) {
        settings.putAll(data);
    }

    // Getters and setters
    public Map<String, Object> getSettings() {
        return settings;
    }

    public void setSettings(Map<String, Object> settings) {
        this.settings = settings;
    }
}

// Redis配置类
@Configuration
class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(ObjectMapper objectMapper) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setKeySerializer(new StringRedisSerializer());
        // 使用Jackson序列化器
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer(objectMapper, null));
        return template;
    }
}

// 模拟攻击载荷示例（FastJSON TemplatesImpl链）
// POST /update/config?dbKey=maliciousKey
// Redis中预先存储的恶意数据：
// {"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
//   "_bytecodes":["base64_encoded_payload"],"_name":"a","_tfactory":{}}