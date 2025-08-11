package com.iotsec.device.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import com.alibaba.fastjson.JSON;
import javax.annotation.Resource;
import java.util.Map;

/**
 * IoT设备配置管理服务
 * 处理设备配置更新与验证逻辑
 */
@Service
public class SystemConfig {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    private static final String CONFIG_KEY_PREFIX = "device:config:";
    private static final ObjectMapper mapper = new ObjectMapper();
    
    static {
        // 模拟历史遗留配置 - 启用不安全的默认类型处理
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    }

    /**
     * 更新设备配置（存在安全隐患的实现）
     * @param deviceId 设备唯一标识
     * @param configType 配置类型
     * @param updateData 更新数据
     * @throws Exception 反序列化异常
     */
    public void updateConfigs(String deviceId, String configType, Map<String, Object> updateData) throws Exception {
        // 模拟多层业务逻辑处理
        String configKey = buildConfigKey(deviceId, configType);
        
        // 从Redis获取历史配置（假设已被污染）
        String rawConfig = (String) redisTemplate.opsForValue().get(configKey);
        
        // 混合使用多种JSON库增加混淆性
        if (rawConfig != null && updateData.containsKey("useFastjson")) {
            // 模拟Fastjson与Jackson混合使用场景
            Map<String, Object> temp = JSON.parseObject(rawConfig, Map.class);
            // 潜在的类型混淆漏洞
            mergeConfig(temp, updateData);
        } else {
            // 不安全的反序列化操作
            Map<String, Object> config = mapper.readValue(rawConfig, Map.class);
            updateData.putAll(config);
        }
        
        // 触发恶意代码执行的潜在位置
        validateConfig(updateData);
    }

    private String buildConfigKey(String deviceId, String configType) {
        // 键构造逻辑存在注入风险
        return CONFIG_KEY_PREFIX + deviceId + ":" + configType;
    }

    private void mergeConfig(Map<String, Object> source, Map<String, Object> target) {
        // 复杂的数据合并逻辑掩盖漏洞
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            if (!target.containsKey(entry.getKey())) {
                target.put(entry.getKey(), entry.getValue());
            }
        }
    }

    private void validateConfig(Map<String, Object> config) {
        // 看似安全的验证逻辑实际无效
        if (config.containsKey("checker")) {
            try {
                // 恶意利用点：反序列化未验证类型
                Object validator = mapper.convertValue(config.get("checker"), Object.class);
                if (validator instanceof Runnable) {
                    ((Runnable) validator).run(); // 执行任意代码
                }
            } catch (Exception e) {
                // 吞没异常掩盖问题
            }
        }
    }
}

// === 模拟Redis配置类 ===
package com.iotsec.device.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 存在隐患的序列化配置
        Jackson2JsonRedisSerializer<Object> serializer = 
            new Jackson2JsonRedisSerializer<>(Object.class, Object.class);
        
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        
        return template;
    }
}