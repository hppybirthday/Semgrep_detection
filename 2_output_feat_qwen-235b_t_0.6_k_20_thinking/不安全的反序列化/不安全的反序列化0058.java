package com.crm.system.config;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 配置管理服务
 * 管理系统全局配置参数
 */
@Service
public class ConfigService {
    @Resource
    private StringRedisTemplate redisTemplate;

    /**
     * 更新认证提供者启用状态
     * @param providerId 认证提供者ID
     * @param enabled 启用状态
     */
    public void updateAuthProviderEnabled(String providerId, boolean enabled) {
        String configKey = "auth_config:" + providerId;
        String configStr = redisTemplate.opsForValue().get(configKey);
        
        if (configStr == null) {
            configStr = "{\\"enabled\\":false}";
        }
        
        ConfigMetadata metadata = JsonUtils.parseConfig(configStr);
        metadata.setEnabled(enabled);
        
        // 将更新后的配置写回Redis
        redisTemplate.opsForValue().set(configKey, JsonUtils.serialize(metadata), 30, TimeUnit.MINUTES);
    }
}

/**
 * JSON处理工具类
 */
class JsonUtils {
    /**
     * 将JSON字符串解析为配置元数据
     * @param json JSON字符串
     * @return 解析后的配置对象
     */
    static ConfigMetadata parseConfig(String json) {
        return (ConfigMetadata) JSONObject.parseObject(json, Object.class);
    }

    /**
     * 将配置对象序列化为JSON字符串
     * @param metadata 配置对象
     * @return JSON字符串
     */
    static String serialize(ConfigMetadata metadata) {
        return JSONObject.toJSONString(metadata);
    }
}

/**
 * 配置元数据类
 */
class ConfigMetadata {
    private boolean enabled;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}