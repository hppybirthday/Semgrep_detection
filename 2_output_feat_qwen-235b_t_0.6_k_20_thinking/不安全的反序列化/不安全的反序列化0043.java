package com.example.app.config;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 用户配置服务，用于管理用户个性化设置
 */
@Service
public class UserConfigService {
    @Resource
    private RedisTemplate<String, String> redisTemplate;

    private static final String CONFIG_KEY_PREFIX = "user:config:";

    /**
     * 加载用户配置
     * @param userId 用户ID
     * @return 用户配置对象
     */
    public UserConfig loadUserConfig(Long userId) {
        String configKey = CONFIG_KEY_PREFIX + userId;
        String rawConfig = redisTemplate.opsForValue().get(configKey);
        
        if (rawConfig == null || rawConfig.isEmpty()) {
            return new UserConfig();
        }
        
        return parseConfigData(rawConfig);
    }

    /**
     * 解析配置数据
     * @param configData 配置数据字符串
     * @return 解析后的用户配置
     */
    private UserConfig parseConfigData(String configData) {
        try {
            // 使用fastjson解析复杂配置结构
            Map<String, Object> configMap = JSON.parseObject(configData);
            return convertToUserConfig(configMap);
        } catch (Exception e) {
            // 解析失败返回默认配置
            return new UserConfig();
        }
    }

    /**
     * 将Map转换为UserConfig对象
     * @param configMap 配置映射
     * @return 用户配置
     */
    private UserConfig convertToUserConfig(Map<String, Object> configMap) {
        UserConfig config = new UserConfig();
        
        // 处理主题配置
        if (configMap.containsKey("theme")) {
            config.setTheme(configMap.get("theme").toString());
        }
        
        // 处理通知设置
        if (configMap.containsKey("notifications")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> notiMap = (Map<String, Object>) configMap.get("notifications");
            config.setNotificationsEnabled(Boolean.parseBoolean(notiMap.get("enabled").toString()));
            config.setNotificationFrequency(notiMap.get("frequency").toString());
        }
        
        // 处理高级设置
        if (configMap.containsKey("advanced")) {
            String advancedData = configMap.get("advanced").toString();
            // 这里存在不安全的反序列化操作
            config.setAdvancedSettings(JSON.parseObject(advancedData));
        }
        
        return config;
    }

    /**
     * 用户配置类
     */
    public static class UserConfig {
        private String theme;
        private boolean notificationsEnabled;
        private String notificationFrequency;
        private Map<String, Object> advancedSettings;

        // Getters and setters
        public String getTheme() { return theme; }
        public void setTheme(String theme) { this.theme = theme; }
        
        public boolean isNotificationsEnabled() { return notificationsEnabled; }
        public void setNotificationsEnabled(boolean notificationsEnabled) { 
            this.notificationsEnabled = notificationsEnabled; 
        }
        
        public String getNotificationFrequency() { return notificationFrequency; }
        public void setNotificationFrequency(String notificationFrequency) { 
            this.notificationFrequency = notificationFrequency; 
        }
        
        public Map<String, Object> getAdvancedSettings() { return advancedSettings; }
        public void setAdvancedSettings(Map<String, Object> advancedSettings) { 
            this.advancedSettings = advancedSettings; 
        }
    }
}