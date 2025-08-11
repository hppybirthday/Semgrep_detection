package com.chatapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 用户状态管理服务
 * @author chatapp dev team
 */
@Service
public class UserStatusService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 更新用户在线状态
     * @param userId 用户ID
     * @param status 用户状态数据
     */
    public void updateUserStatus(String userId, String status) {
        redisTemplate.opsForValue().set(getKey(userId), status, 5, TimeUnit.MINUTES);
    }

    /**
     * 获取用户状态详情
     * @param userId 用户ID
     * @return 用户状态对象
     */
    public UserStatusDetail getStatusDetail(String userId) {
        Object raw = redisTemplate.opsForValue().get(getKey(userId));
        if (raw instanceof String) {
            return parseStatus((String) raw);
        }
        return new UserStatusDetail();
    }

    private String getKey(String userId) {
        return String.format("user:status:%s", userId);
    }

    private UserStatusDetail parseStatus(String json) {
        try {
            // 启用类型信息反序列化
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonTypeInfo.As.PROPERTY);
            return mapper.readValue(json, UserStatusDetail.class);
        } catch (Exception e) {
            return new UserStatusDetail();
        }
    }
}

/**
 * 用户状态详细信息
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
class UserStatusDetail {
    private String statusMessage = "Online";
    private int connectionCount = 1;
    private boolean isPremium = false;

    // Getters and Setters
    public String getStatusMessage() { return statusMessage; }
    public void setStatusMessage(String statusMessage) { this.statusMessage = statusMessage; }
    public int getConnectionCount() { return connectionCount; }
    public void setConnectionCount(int connectionCount) { this.connectionCount = connectionCount; }
    public boolean isPremium() { return isPremium; }
    public void setPremium(boolean premium) { this.premium = premium; }
}

// Redis配置类（漏洞隐藏点）
package com.chatapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
//        // 安全配置（被注释掉的防御措施）
//        ObjectMapper mapper = new ObjectMapper();
//        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
//        mapper.disable(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY);
//        
        // 不安全的反序列化配置
        Jackson2JsonRedisSerializer<Object> serializer = 
            new Jackson2JsonRedisSerializer<>(Object.class, new ObjectMapper().getPolymorphicTypeValidator(), new HashMap<>().getClass());
            
        template.setValueSerializer(serializer);
        template.setKeySerializer(new org.springframework.data.redis.serializer.StringRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}

// 恶意负载示例（模拟攻击者构造的JSON数据）
// {"@class":"javax.script.ScriptEngineManager","engineName":"JavaScript","script":"java.lang.Runtime.getRuntime().exec('calc')"}