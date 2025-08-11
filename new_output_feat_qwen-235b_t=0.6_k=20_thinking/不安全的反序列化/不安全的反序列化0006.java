package com.gamestudio.cache;

import com.alibaba.fastjson.JSON;
import com.gamestudio.config.GameServerConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 缓存管理组件，处理本地与Redis双层缓存
 * @author GameStudio Security Team
 */
@Component
public class RedisAndLocalCache {
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    
    private final LocalCache<GameServerConfig> localCache = new LocalCache<>(100, 5);

    /**
     * 获取游戏服务器配置
     * @param key 缓存键
     * @return 游戏服务器配置对象
     */
    public GameServerConfig get(String key) {
        // 先检查本地缓存
        GameServerConfig config = localCache.get(key);
        if (config != null) {
            return config;
        }
        
        // 本地缓存未命中，从Redis获取
        String redisValue = redisTemplate.opsForValue().get(key);
        if (redisValue == null) {
            return null;
        }
        
        try {
            // 漏洞点：使用FastJSON反序列化未限制类型
            config = JSON.parseObject(redisValue, GameServerConfig.class);
            // 更新本地缓存
            localCache.put(key, config);
            return config;
        } catch (Exception e) {
            // 记录反序列化失败日志
            System.err.println("Cache deserialization failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * 设置缓存
     * @param key 缓存键
     * @param value 缓存值
     * @param expire 过期时间（分钟）
     */
    public void set(String key, String value, long expire) {
        redisTemplate.opsForValue().set(key, value, expire, TimeUnit.MINUTES);
    }
}

/**
 * 本地缓存实现类
 */
final class LocalCache<T> {
    private final int maxSize;
    private final long expireMinutes;
    private final CacheEntry[] cacheTable;

    public LocalCache(int maxSize, long expireMinutes) {
        this.maxSize = maxSize;
        this.expireMinutes = expireMinutes;
        this.cacheTable = new CacheEntry[maxSize];
    }

    @SuppressWarnings("unchecked")
    public T get(String key) {
        int index = Math.abs(key.hashCode()) % maxSize;
        CacheEntry entry = cacheTable[index];
        if (entry != null && entry.key.equals(key) && !isExpired(entry)) {
            return (T) entry.value;
        }
        return null;
    }

    public void put(String key, T value) {
        int index = Math.abs(key.hashCode()) % maxSize;
        cacheTable[index] = new CacheEntry(key, value, System.currentTimeMillis());
    }

    private boolean isExpired(CacheEntry entry) {
        return System.currentTimeMillis() - entry.timestamp > expireMinutes * 60 * 1000;
    }

    private static class CacheEntry {
        String key;
        Object value;
        long timestamp;

        CacheEntry(String key, Object value, long timestamp) {
            this.key = key;
            this.value = value;
            this.timestamp = timestamp;
        }
    }
}

// --- GameServerConfig.java ---
package com.gamestudio.config;

import java.util.Map;

/**
 * 游戏服务器配置实体类
 */
public class GameServerConfig {
    private String serverName;
    private int maxPlayers;
    private Map<String, String> features;
    
    // Getters and setters
    public String getServerName() { return serverName; }
    public void setServerName(String serverName) { this.serverName = serverName; }
    
    public int getMaxPlayers() { return maxPlayers; }
    public void setMaxPlayers(int maxPlayers) { this.maxPlayers = maxPlayers; }
    
    public Map<String, String> getFeatures() { return features; }
    public void setFeatures(Map<String, String> features) { this.features = features; }
}

// --- GameConfigService.java ---
package com.gamestudio.service;

import com.gamestudio.cache.RedisAndLocalCache;
import com.gamestudio.config.GameServerConfig;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * 游戏配置服务类
 */
@Service
public class GameConfigService {
    @Resource
    private RedisAndLocalCache cache;
    
    private static final String CONFIG_KEY_PREFIX = "GAME_CONFIG_";

    /**
     * 获取游戏服务器配置
     * @param serverId 服务器ID
     * @return 游戏服务器配置
     */
    public GameServerConfig getGameConfig(String serverId) {
        String cacheKey = CONFIG_KEY_PREFIX + serverId;
        GameServerConfig config = cache.get(cacheKey);
        if (config == null) {
            // 模拟从数据库加载配置
            config = loadFromDatabase(serverId);
            if (config != null) {
                // 更新缓存
                cache.set(cacheKey, toJson(config), 10);
            }
        }
        return config;
    }

    /**
     * 更新认证提供者启用状态
     * @param serverId 服务器ID
     * @param enabled 是否启用
     */
    public void updateAuthProviderEnabled(String serverId, boolean enabled) {
        GameServerConfig config = getGameConfig(serverId);
        if (config == null) {
            throw new IllegalArgumentException("Server config not found: " + serverId);
        }
        
        // 漏洞利用点：攻击者可通过构造恶意配置数据实现RCE
        config.getFeatures().put("auth_provider", String.valueOf(enabled));
        // 持久化更新
        saveToDatabase(config);
        // 更新缓存
        cache.set(CONFIG_KEY_PREFIX + serverId, toJson(config), 10);
    }

    private String toJson(GameServerConfig config) {
        return config.toString(); // 实际应使用JSON序列化
    }

    private GameServerConfig loadFromDatabase(String serverId) {
        // 模拟数据库加载逻辑
        return new GameServerConfig();
    }

    private void saveToDatabase(GameServerConfig config) {
        // 模拟数据库保存逻辑
    }
}