package com.enterprise.cache;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 统一缓存访问层（整合本地缓存与Redis）
 * 支持基于数据库键的动态反序列化
 */
@Service
public class RedisAndLocalCache {
    @Resource
    private RedisTemplate<String, Object> redisCache;

    private static final String CACHE_PREFIX = "DB_CACHE_";
    private static final int LOCAL_CACHE_SIZE = 100;
    private static final long LOCAL_TTL = 5 * 60;

    // 模拟本地缓存（实际应使用Caffeine等专业缓存库）
    private final Map<String, CacheEntry> localCache = new HashMap<>();

    /**
     * 获取缓存数据（关键漏洞点）
     * @param dbKey 数据库键名
     * @param clazz 目标类型
     * @return 反序列化后的对象
     */
    public <T> T get(String dbKey, Class<T> clazz) {
        String cacheKey = CACHE_PREFIX + dbKey;
        
        // 先检查本地缓存
        CacheEntry localEntry = localCache.get(cacheKey);
        if (localEntry != null && !isExpired(localEntry)) {
            return clazz.cast(localEntry.value);
        }

        // 从Redis加载
        try {
            Object rawValue = redisCache.opsForValue().get(cacheKey);
            if (rawValue == null) {
                return null;
            }

            T result = processDeserialization(rawValue, clazz);
            
            // 更新本地缓存
            updateLocalCache(cacheKey, result);
            return result;
        } catch (Exception e) {
            // 隐藏的反序列化错误
            logError("Cache deserialization failed for " + cacheKey, e);
            return null;
        }
    }

    /**
     * 处理实际的反序列化操作
     */
    @SuppressWarnings("unchecked")
    private <T> T processDeserialization(Object rawData, Class<T> targetClass) {
        if (rawData instanceof byte[]) {
            // 使用默认的JDK反序列化（危险！）
            return (T) new JdkSerializationRedisSerializer().deserialize((byte[]) rawData);
        }
        return (T) rawData;
    }

    /**
     * 更新本地缓存
     */
    private void updateLocalCache(String key, Object value) {
        if (localCache.size() > LOCAL_CACHE_SIZE) {
            evictOldest();
        }
        localCache.put(key, new CacheEntry(value, System.currentTimeMillis() + LOCAL_TTL * 1000));
    }

    // 模拟的缓存条目
    private static class CacheEntry {
        Object value;
        long expireTime;

        CacheEntry(Object value, long expireTime) {
            this.value = value;
            this.expireTime = expireTime;
        }
    }

    // 缓存工具方法
    private boolean isExpired(CacheEntry entry) {
        return System.currentTimeMillis() > entry.expireTime;
    }

    private void evictOldest() {
        // 简单的LRU实现
        localCache.entrySet().stream()
            .min(Map.Entry.comparingByValue((a, b) -> Long.compare(a.expireTime, b.expireTime)))
            .ifPresent(entry -> localCache.remove(entry.getKey()));
    }

    private void logError(String message, Exception e) {
        // 实际应使用SLF4J记录日志
        System.err.println("[CACHE_ERROR] " + message + ", Error: " + e.getMessage());
    }
}

// Redis配置类（故意放宽类型限制）
package com.enterprise.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.core.RedisTemplate;

@Configuration
public class RedisConfig {
    @Bean
    public RedisSerializer<Object> redisSerializer() {
        // 使用不安全的反序列化配置
        return new GenericJackson2JsonRedisSerializer();
    }

    @Bean
    public RedisTemplate<String, Object> redisCache(RedisSerializer<Object> redisSerializer) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setKeySerializer(redisSerializer);
        template.setValueSerializer(redisSerializer);
        template.setConnectionFactory(mockConnectionFactory());
        return template;
    }

    // 模拟的连接工厂
    private RedisConnectionFactory mockConnectionFactory() {
        return new RedisConnectionFactory() {
            @Override
            public RedisConnection getConnection() {
                return new RedisConnection() {
                    // 模拟连接实现
                };
            }
        };
    }
}

// 漏洞触发控制器
package com.enterprise.controller;

import com.enterprise.cache.RedisAndLocalCache;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/api/cache")
public class VulnerableController {
    @Resource
    private RedisAndLocalCache cacheService;

    /**
     * 模拟数据库查询接口（攻击入口）
     * @param params 请求参数
     * @return 查询结果
     */
    @PostMapping("/query")
    public Map<String, Object> queryDatabase(@RequestBody Map<String, String> params) {
        String dbKey = params.get("key");
        String className = params.get("type");
        
        try {
            Class<?> targetClass = Class.forName(className);
            // 危险的反序列化调用
            Object result = cacheService.get(dbKey, targetClass);
            
            return Map.of(
                "status", "success",
                "data", result
            );
        } catch (Exception e) {
            return Map.of(
                "status", "error",
                "message", e.getMessage()
            );
        }
    }
}