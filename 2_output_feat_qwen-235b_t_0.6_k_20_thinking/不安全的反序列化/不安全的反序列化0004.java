package com.example.config;

import com.alibaba.fastjson.JSON;
import com.example.service.RedisTokenStore;
import com.example.model.AuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 配置管理器
 * 用于处理认证提供者配置的更新和存储
 */
@Component
public class ConfigMap {
    @Autowired
    private RedisTokenStore redisTokenStore;

    /**
     * 更新认证提供者状态
     * @param configJson 新的配置JSON字符串
     */
    public void updateAuthProviderEnabled(String configJson) {
        if (configJson == null || configJson.isEmpty()) {
            return;
        }

        // 解析配置字符串为Map
        Map<String, Object> configMap = JSON.parseObject(configJson, Map.class);
        if (configMap.containsKey("authProvider")) {
            String providerJson = configMap.get("authProvider").toString();
            // 从Redis获取认证提供者实例
            AuthProvider provider = redisTokenStore.getAuthProvider(providerJson);
            if (provider != null) {
                provider.setEnabled(true);
                redisTokenStore.saveAuthProvider(provider);
            }
        }
    }
}

/**
 * Redis令牌存储服务
 * 用于处理认证提供者的序列化和反序列化
 */
@Component
class RedisTokenStore {
    // 模拟Redis操作
    private final Map<String, String> redisStorage = new java.util.HashMap<>();

    /**
     * 获取认证提供者实例
     * @param key Redis键值
     * @return 反序列化后的AuthProvider对象
     */
    public AuthProvider getAuthProvider(String key) {
        String json = redisStorage.getOrDefault(key, null);
        if (json == null) {
            return null;
        }
        // 使用FastJSON反序列化
        return JSON.parseObject(json, AuthProvider.class);
    }

    /**
     * 存储认证提供者实例
     * @param provider 要存储的AuthProvider对象
     */
    public void saveAuthProvider(AuthProvider provider) {
        String json = JSON.toJSONString(provider);
        redisStorage.put(provider.getId(), json);
    }
}

/**
 * 认证提供者模型类
 */
package com.example.model;

public class AuthProvider {
    private String id;
    private boolean enabled;

    public AuthProvider() {}

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}