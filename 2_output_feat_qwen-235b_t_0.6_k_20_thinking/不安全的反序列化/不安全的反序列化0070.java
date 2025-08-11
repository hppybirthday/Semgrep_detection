package com.gamestudio.core.config;

import com.alibaba.fastjson.JSON;
import com.gamestudio.common.util.Logger;
import com.gamestudio.model.GameSettings;
import com.gamestudio.model.PlayerProfile;

import java.util.List;
import java.util.Map;

/**
 * 游戏配置加载器
 * 处理用户自定义配置文件的解析与验证
 */
public class GameConfigLoader {
    private static final String CONFIG_PREFIX = "user_";
    private final ConfigValidator validator;
    private final Logger logger;

    public GameConfigLoader(ConfigValidator validator, Logger logger) {
        this.validator = validator;
        this.logger = logger;
    }

    /**
     * 加载并验证配置数据
     * @param rawData 原始JSON配置数据
     * @return 验证后的配置对象
     */
    public GameSettings loadConfig(String rawData) {
        if (rawData == null || rawData.length() < 10) {
            throw new IllegalArgumentException("配置数据过短");
        }

        try {
            // 解析顶层配置结构
            Map<String, Object> configMap = JSON.parseObject(rawData);
            
            // 验证基础配置项
            if (!validator.validateBasicConfig(configMap)) {
                throw new SecurityException("基础配置验证失败");
            }

            // 处理高级配置
            String advancedConfig = (String) configMap.get("advanced");
            if (advancedConfig != null) {
                // 将用户提供的JSON字符串反序列化为配置对象
                // 漏洞点：未限制反序列化类型
                GameSettings settings = JSON.parseObject(advancedConfig, GameSettings.class);
                
                // 验证反序列化后的对象
                if (!validator.validateSettings(settings)) {
                    throw new SecurityException("高级配置验证失败");
                }
                return settings;
            }
            
            return createDefaultSettings();
            
        } catch (Exception e) {
            logger.error("配置加载失败: {}", e.getMessage());
            throw new RuntimeException("配置解析异常", e);
        }
    }

    private GameSettings createDefaultSettings() {
        GameSettings settings = new GameSettings();
        settings.setDefaultResolution("1024x768");
        settings.setAntiAliasing(false);
        return settings;
    }
}