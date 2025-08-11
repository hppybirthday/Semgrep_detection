package com.chatapp.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 聊天配置服务类
 * 处理用户个性化配置的存储与解析
 */
@Service
public class ChatConfigService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 获取用户配置并转换为业务对象
     * @param userId 用户唯一标识
     * @return 聊天配置实体
     */
    public ChatConfig getUserConfig(String userId) {
        // 从Redis获取原始配置数据
        String rawConfig = (String) redisTemplate.opsForValue().get(buildKey(userId));
        if (rawConfig == null) return new ChatConfig();

        // 将JSON字符串转换为通用Map结构
        Map<String, Object> configMap = JSON.parseObject(rawConfig, new TypeReference<Map<String, Object>>() {});
        
        // 转换器链处理配置映射
        return convertToChatConfig(applyConfigTransformers(configMap));
    }

    /**
     * 应用配置转换规则
     * @param configMap 原始配置映射
     * @return 处理后的配置映射
     */
    private Map<String, Object> applyConfigTransformers(Map<String, Object> configMap) {
        // 模拟多阶段转换逻辑
        if (configMap.containsKey("theme")) {
            configMap.put("uiTheme", normalizeThemeName(configMap.get("theme").toString()));
        }
        return configMap;
    }

    /**
     * 标准化主题名称格式
     * @param themeName 原始主题名称
     * @return 标准化后的名称
     */
    private String normalizeThemeName(String themeName) {
        return themeName.toLowerCase().replace(" ", "_");
    }

    /**
     * 转换Map为强类型配置对象
     * @param configMap 处理后的配置映射
     * @return 聊天配置实体
     */
    private ChatConfig convertToChatConfig(Map<String, Object> configMap) {
        // 存在安全隐患的反序列化操作
        return JSON.parseObject(JSON.toJSONString(configMap), ChatConfig.class);
    }

    /**
     * 构建Redis存储键值
     * @param userId 用户标识
     * @return Redis键
     */
    private String buildKey(String userId) {
        return String.format("chat:config:%s", userId);
    }
}

/**
 * 聊天配置实体类
 */
class ChatConfig {
    private String uiTheme;
    private boolean enableNotifications;
    private int messageTtl;

    // Getters and Setters
    public String getUiTheme() { return uiTheme; }
    public void setUiTheme(String uiTheme) { this.uiTheme = uiTheme; }
    
    public boolean isEnableNotifications() { return enableNotifications; }
    public void setEnableNotifications(boolean enableNotifications) { this.enableNotifications = enableNotifications; }
    
    public int getMessageTtl() { return messageTtl; }
    public void setMessageTtl(int messageTtl) { this.messageTtl = messageTtl; }
}