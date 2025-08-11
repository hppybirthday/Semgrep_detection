package com.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.model.UserProfile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 用户配置服务
 * 提供用户个性化设置的存储与读取功能
 */
@Service
public class UserConfigService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 保存用户个性化配置
     * @param userId 用户ID
     * @param configJson 用户配置JSON字符串
     * @throws Exception 反序列化异常
     */
    public void saveUserConfig(String userId, String configJson) throws Exception {
        UserProfile profile = objectMapper.readValue(configJson, UserProfile.class);
        // 生成缓存key并存储
        String cacheKey = generateCacheKey(userId);
        redisTemplate.opsForValue().set(cacheKey, profile, 30, TimeUnit.MINUTES);
    }

    /**
     * 获取用户个性化配置
     * @param userId 用户ID
     * @return 用户配置对象
     */
    public UserProfile getUserConfig(String userId) {
        String cacheKey = generateCacheKey(userId);
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        // 直接返回Redis中的对象可能导致反序列化漏洞
        return cached instanceof UserProfile ? (UserProfile) cached : createDefaultProfile();
    }

    private String generateCacheKey(String userId) {
        return "user:config:" + userId;
    }

    private UserProfile createDefaultProfile() {
        return new UserProfile("default_prefs", 1);
    }
}