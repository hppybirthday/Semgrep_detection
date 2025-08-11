package com.example.app.service;

import com.alibaba.fastjson.JSON;
import com.example.app.model.UserProfile;
import com.example.app.util.RedisUtil;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 用户偏好设置服务
 * 提供用户配置的存储与解析功能
 */
@Service
public class UserPreferenceService {
    @Resource
    private RedisUtil redisUtil;

    /**
     * 存储用户偏好设置
     * @param userId 用户唯一标识
     * @param preferenceData 偏好数据JSON字符串
     */
    public void savePreference(String userId, String preferenceData) {
        if (!isValidPreferenceFormat(preferenceData)) {
            throw new IllegalArgumentException("Invalid preference format");
        }
        
        // 存储原始JSON数据到Redis
        redisUtil.set(getPreferenceKey(userId), preferenceData, 30 * 60);
    }

    /**
     * 加载用户偏好设置
     * @param userId 用户唯一标识
     * @return 解析后的偏好对象
     */
    public Object loadPreference(String userId) {
        String preferenceJson = (String) redisUtil.get(getPreferenceKey(userId));
        if (!StringUtils.hasText(preferenceJson)) {
            return new UserProfile();
        }
        
        // 调用链隐藏的反序列化漏洞点
        return parsePreferenceData(preferenceJson);
    }

    /**
     * 验证JSON基本格式（仅验证语法正确性）
     */
    private boolean isValidPreferenceFormat(String jsonData) {
        if (!StringUtils.hasText(jsonData)) {
            return false;
        }
        
        try {
            // 仅验证语法正确性，不处理内容安全
            JSON.parseObject(jsonData);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 解析偏好数据（关键漏洞点）
     * 注意：此处使用通用Object类型隐藏实际处理逻辑
     */
    private Object parsePreferenceData(String jsonData) {
        // Fastjson默认反序列化配置存在安全隐患
        // 未限制反序列化类型，未启用安全校验
        return JSON.parseObject(jsonData, Object.class);
    }

    /**
     * 构造Redis存储键名
     * @param userId 用户ID（外部输入）
     */
    private String getPreferenceKey(String userId) {
        // 外部输入直接拼接缓存键
        return String.format("user:preference:%s", userId);
    }
}

package com.example.app.util;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * Redis操作工具类
 */
@Component
public class RedisUtil {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public void set(String key, Object value, long expireTime) {
        redisTemplate.opsForValue().set(key, value, expireTime, TimeUnit.SECONDS);
    }

    public Object get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void delete(String key) {
        redisTemplate.delete(key);
    }
}

package com.example.app.model;

import lombok.Data;

/**
 * 用户配置实体类
 * 用于演示正常业务场景的数据结构
 */
@Data
public class UserProfile {
    private String theme;
    private String language;
    private int fontSize;
    private boolean notificationsEnabled;
}