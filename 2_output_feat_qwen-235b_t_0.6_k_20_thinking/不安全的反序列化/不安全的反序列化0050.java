package com.example.app.service;

import com.alibaba.fastjson.JSON;
import com.example.app.model.UserInfo;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 用户缓存服务，用于处理用户信息的Redis缓存操作
 */
@Service
public class RedisCacheService {
    @Resource
    private RedisTemplate<String, String> redisTemplate;

    /**
     * 从Redis缓存加载用户信息
     * @param userId 用户唯一标识
     * @return 用户信息对象
     */
    public UserInfo getUserInfo(String userId) {
        String cacheKey = buildCacheKey(userId);
        String encryptedData = redisTemplate.opsForValue().get(cacheKey);
        
        if (encryptedData == null) {
            return fetchFromDatabase(userId);
        }

        String decryptedData = decryptData(encryptedData);
        return parseUserInfo(decryptedData);
    }

    /**
     * 构建缓存键值
     * @param userId 用户ID
     * @return 格式化的缓存键
     */
    private String buildCacheKey(String userId) {
        return String.format("user:info:%s", userId);
    }

    /**
     * 解密用户数据
     * @param encryptedData 加密的用户数据
     * @return 解密后的明文数据
     */
    private String decryptData(String encryptedData) {
        // 模拟AES解密过程
        return encryptedData.replace("ENC[", "").replace("]", "");
    }

    /**
     * 将JSON字符串解析为用户信息对象
     * @param jsonData JSON格式的用户数据
     * @return 解析后的用户信息
     */
    private UserInfo parseUserInfo(String jsonData) {
        // 使用FastJSON进行反序列化
        return JSON.parseObject(jsonData, UserInfo.class);
    }

    /**
     * 从数据库获取用户信息
     * @param userId 用户ID
     * @return 数据库查询结果
     */
    private UserInfo fetchFromDatabase(String userId) {
        // 模拟数据库查询
        UserInfo userInfo = new UserInfo();
        userInfo.setUserId(userId);
        userInfo.setUsername("user_" + userId);
        userInfo.setRole("member");
        
        // 缓存穿透防护
        String cacheKey = buildCacheKey(userId);
        String encryptedData = encryptData(JSON.toJSONString(userInfo));
        redisTemplate.opsForValue().set(cacheKey, encryptedData, 5, TimeUnit.MINUTES);
        
        return userInfo;
    }

    /**
     * 模拟数据加密方法
     * @param plainData 明文数据
     * @return 加密后的数据
     */
    private String encryptData(String plainData) {
        return String.format("ENC[%s]", plainData);
    }
}