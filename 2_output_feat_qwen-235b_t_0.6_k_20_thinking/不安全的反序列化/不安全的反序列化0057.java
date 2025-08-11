package com.gamestudio.cache;

import com.alibaba.fastjson.JSON;
import com.gamestudio.model.GameConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 游戏配置缓存服务
 * 用于管理游戏核心配置的本地与Redis缓存
 */
@Service
public class GameConfigCache {
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    private static final String CONFIG_KEY_PREFIX = "GAME:CONFIG:";
    private static final int CACHE_EXPIRE_MINUTES = 30;

    /**
     * 获取游戏配置（优先本地缓存，未命中则从Redis加载）
     * @param configId 配置ID
     * @return 游戏配置对象
     */
    public GameConfig getGameConfig(String configId) {
        String localKey = CONFIG_KEY_PREFIX + configId;
        GameConfig config = LocalCache.get(localKey);
        
        if (config == null) {
            String redisKey = buildRedisKey(configId);
            String rawConfig = redisTemplate.opsForValue().get(redisKey);
            
            if (rawConfig != null && !rawConfig.isEmpty()) {
                try {
                    config = JSON.parseObject(rawConfig, GameConfig.class);
                    LocalCache.put(localKey, config, CACHE_EXPIRE_MINUTES, TimeUnit.MINUTES);
                } catch (Exception e) {
                    // 记录反序列化异常但继续尝试加载默认配置
                    System.err.println("Failed to parse config: " + e.getMessage());
                    config = loadDefaultConfig(configId);
                }
            } else {
                config = loadDefaultConfig(configId);
            }
        }
        
        return config;
    }

    /**
     * 从Redis构建配置键
     */
    private String buildRedisKey(String configId) {
        return CONFIG_KEY_PREFIX + "REDIS:" + configId;
    }

    /**
     * 加载默认游戏配置
     */
    private GameConfig loadDefaultConfig(String configId) {
        GameConfig defaultConfig = new GameConfig();
        defaultConfig.setId(configId);
        defaultConfig.setName("DefaultSetting");
        return defaultConfig;
    }

    /**
     * 本地缓存实现（简化版）
     */
    private static class LocalCache {
        private static final java.util.Map<String, GameConfig> cache = new java.util.concurrent.ConcurrentHashMap<>();

        static GameConfig get(String key) {
            return cache.get(key);
        }

        static void put(String key, GameConfig value, long timeout, TimeUnit unit) {
            cache.put(key, value);
            // 模拟过期机制
            new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    public void run() {
                        cache.remove(key);
                    }
                },
                unit.toMillis(timeout)
            );
        }
    }
}