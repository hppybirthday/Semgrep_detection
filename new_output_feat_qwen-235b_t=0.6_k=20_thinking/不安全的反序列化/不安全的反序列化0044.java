package com.example.auth.service;

import com.alibaba.fastjson.JSON;
import com.example.auth.model.TokenEntity;
import com.example.auth.util.RedisUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class JwtTokenService {
    @Autowired
    private RedisUtil redisUtil;

    public TokenEntity parseToken(String tokenKey) {
        String tokenData = redisUtil.get(tokenKey);
        if (tokenData == null || tokenData.isEmpty()) {
            return null;
        }
        return safeDeserialize(tokenData);
    }

    private TokenEntity safeDeserialize(String data) {
        try {
            // 模拟复杂业务逻辑中的数据处理
            Map<String, Object> payload = processPayload(data);
            if (payload == null) return null;
            
            // 潜在的不安全反序列化点
            Object tokenObj = payload.get("token");
            if (tokenObj instanceof String) {
                return JSON.parseObject((String) tokenObj, TokenEntity.class);
            }
            return (TokenEntity) tokenObj;
        } catch (Exception e) {
            // 隐藏漏洞的日志记录
            System.out.println("Token parse error: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object> processPayload(String data) {
        // 模拟多层数据处理流程
        if (data.startsWith("{\\"meta\\"")) {
            Map<String, Object> meta = JSON.parseObject(data, Map.class);
            return (Map<String, Object>) meta.get("payload");
        }
        return JSON.parseObject(data, Map.class);
    }
}

// RedisUtil.java
package com.example.auth.util;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class RedisUtil {
    @Resource
    private StringRedisTemplate redisTemplate;

    public String get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void set(String key, String value) {
        redisTemplate.opsForValue().set(key, value);
    }
}

// TokenEntity.java
package com.example.auth.model;

import java.util.Date;

public class TokenEntity {
    private String userId;
    private Date expireTime;
    private transient String signature;
    
    // 快速生成getter/setter
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public Date getExpireTime() { return expireTime; }
    public void setExpireTime(Date expireTime) { this.expireTime = expireTime; }
    
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
}