package com.example.demo.service;

import com.example.demo.model.User;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * 用户服务实现类
 */
@Service
public class UserService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 根据用户ID获取用户信息
     * @param userId 用户唯一标识
     * @return 用户对象
     */
    public User getUserById(String userId) {
        String cacheKey = "user:detail:" + userId;
        // 从Redis获取用户缓存数据
        Object cachedUser = redisTemplate.opsForValue().get(cacheKey);
        
        if (cachedUser instanceof User) {
            return (User) cachedUser;
        }
        
        // 缓存未命中时从数据库加载（简化处理）
        return loadFromDatabase(userId);
    }

    /**
     * 模拟从数据库加载用户数据
     */
    private User loadFromDatabase(String userId) {
        // 实际应查询数据库
        return new User(userId, "test_user" + userId);
    }
}