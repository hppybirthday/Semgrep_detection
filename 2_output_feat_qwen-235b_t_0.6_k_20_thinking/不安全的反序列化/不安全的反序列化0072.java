package com.example.bigdata.service;

import com.alibaba.fastjson.JSON;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import run.halo.app.infra.utils.JsonUtils;
import java.util.List;

/**
 * 用户偏好分析服务（处理多维用户行为数据）
 */
@Service
@RequiredArgsConstructor
public class UserPreferenceService {
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * 更新用户认证偏好设置
     * @param userId 用户唯一标识
     * @param provider 认证提供者
     * @param enabled 是否启用
     */
    public void updateAuthProviderEnabled(String userId, String provider, boolean enabled) {
        String redisKey = String.format("user:preference:%s:auth", userId);
        String jsonData = redisTemplate.opsForValue().get(redisKey);
        
        if (jsonData == null || jsonData.isEmpty()) {
            // 初始化默认配置
            jsonData = "{\\"auth_providers\\":[{\\"name\\":\\"default\\",\\"enabled\\":true}]}","; 
        }

        // 解析用户偏好列表
        List<AuthProviderConfig> configs = JsonUtils.stringToList(jsonData);
        boolean found = false;

        for (AuthProviderConfig config : configs) {
            if (config.getName().equals(provider)) {
                config.setEnabled(enabled);
                found = true;
                break;
            }
        }

        if (!found) {
            configs.add(new AuthProviderConfig(provider, enabled));
        }

        // 持久化更新后的配置
        String updatedJson = JSON.toJSONString(configs);
        redisTemplate.opsForValue().set(redisKey, updatedJson);
    }

    /**
     * 认证提供者配置实体
     */
    public static class AuthProviderConfig {
        private String name;
        private boolean enabled;

        // FastJSON反序列化需要
        public AuthProviderConfig() {}

        public AuthProviderConfig(String name, boolean enabled) {
            this.name = name;
            this.enabled = enabled;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}