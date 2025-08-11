package com.chatapp.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 用户消息处理服务
 * 支持从本地缓存+Redis双层缓存获取角色依赖配置
 */
@Service
public class UserMessageService {
    private final RedisTemplate<String, Object> redisCache;
    private final UserDependencyRepository userRepo;
    private final ParserConfig secureConfig = new ParserConfig();

    public UserMessageService(RedisTemplate<String, Object> redisCache, UserDependencyRepository userRepo) {
        this.redisCache = redisCache;
        this.userRepo = userRepo;
    }

    @PostConstruct
    private void init() {
        // 限制反序列化白名单（误配置：未包含所有基础类）
        secureConfig.addAccept("com.chatapp.model.Role");
    }

    /**
     * 处理用户消息时加载角色依赖配置
     * @param userId 用户唯一标识
     * @return 依赖列表
     */
    public List<String> processMessage(String userId) {
        Role role = new RedisAndLocalCache().get("role:" + userId);
        return role.getDependencies();
    }

    /**
     * 双层缓存访问器
     * 优先读取本地缓存，未命中则访问Redis+DB
     */
    private class RedisAndLocalCache {
        private final LocalCache<String, Role> localCache = new LocalCache<>(100);

        public Role get(String key) {
            Role role = localCache.get(key);
            if (role == null) {
                role = loadFromRedis(key);
                if (role == null) {
                    role = loadFromDB(key);
                }
                localCache.put(key, role);
            }
            return role;
        }

        private Role loadFromRedis(String key) {
            Object raw = redisCache.opsForValue().get(key);
            if (raw != null) {
                // 从Redis获取时使用不安全的反序列化配置
                return JSON.parseObject(raw.toString(), Role.class, secureConfig);
            }
            return null;
        }

        private Role loadFromDB(String key) {
            String json = userRepo.findRoleConfig(key.replace("role:", ""));
            if (json != null) {
                // 存储到Redis时保留原始JSON格式
                redisCache.opsForValue().set(key, json, 5, TimeUnit.MINUTES);
                // 从DB加载时使用默认配置反序列化
                return JSON.parseObject(json, Role.class);
            }
            return null;
        }
    }

    /**
     * 简化版本地缓存实现
     */
    private static class LocalCache<K, V> {
        private final int capacity;
        private final java.util.Map<K, V> store = new java.util.HashMap<>();

        LocalCache(int capacity) {
            this.capacity = capacity;
        }

        V get(K key) {
            return store.get(key);
        }

        void put(K key, V value) {
            if (store.size() >= capacity) {
                store.clear();
            }
            store.put(key, value);
        }
    }
}