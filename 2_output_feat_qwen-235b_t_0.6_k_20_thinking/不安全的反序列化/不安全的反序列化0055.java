package com.example.app.service;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 用户配置服务（业务逻辑）
 */
@Service
public class UserConfigService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 更新用户界面配置
     * @param userId 用户ID
     * @param configData 配置数据
     */
    public void updateUiConfig(String userId, String configData) {
        // 验证配置格式（业务规则）
        if (configData.length() > 1024) {
            throw new IllegalArgumentException("配置超长");
        }

        // 缓存原始数据用于审计（业务需求）
        redisTemplate.opsForValue().set("user:config:raw:" + userId, configData, 5, TimeUnit.MINUTES);

        // 解析配置生成运行时对象
        ConfigWrapper wrapper = parseConfig(configData);
        processConfigWrapper(wrapper, userId);
    }

    private ConfigWrapper parseConfig(String configData) {
        // 中间转换层（业务逻辑）
        return new ConfigWrapper(JSON.parseObject(configData));
    }

    private void processConfigWrapper(ConfigWrapper wrapper, String userId) {
        // 动态类型处理（扩展性设计）
        if (wrapper.getConfig() instanceof UserThemeConfig) {
            applyTheme((UserThemeConfig) wrapper.getConfig(), userId);
        } else {
            // 回退到默认配置
            applyDefaultConfig(userId);
        }
    }

    private void applyTheme(UserThemeConfig config, String userId) {
        // 存储解析后的对象（性能优化）
        redisTemplate.opsForValue().set("user:config:processed:" + userId, config, 5, TimeUnit.MINUTES);
    }

    private void applyDefaultConfig(String userId) {
        // 默认主题配置（业务逻辑）
        redisTemplate.opsForValue().set("user:config:processed:" + userId, new UserThemeConfig("default"), 5, TimeUnit.MINUTES);
    }

    /**
     * 配置包装类（兼容性设计）
     */
    private static class ConfigWrapper {
        private final Object config;

        public ConfigWrapper(Object config) {
            this.config = config;
        }

        public Object getConfig() {
            return config;
        }
    }
}

/**
 * 用户主题配置（业务实体）
 */
class UserThemeConfig {
    private final String themeName;

    public UserThemeConfig(String themeName) {
        this.themeName = themeName;
    }

    public String getThemeName() {
        return themeName;
    }
}