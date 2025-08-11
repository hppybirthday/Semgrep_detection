package com.example.paymentservice.config;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 支付系统配置服务
 * 处理跨商户的配置缓存逻辑
 */
@Service
public class PaymentConfigService {
    @Resource
    private RedisTemplate<String, String> redisTemplate;

    private static final String CONFIG_KEY_PREFIX = "payment:config:";
    private static final Long CACHE_EXPIRE = 30L;

    /**
     * 获取商户系统设置
     * 从Redis缓存加载配置信息
     */
    public SystemSetting getSystemSetting(String merchantId) {
        String cacheKey = CONFIG_KEY_PREFIX + merchantId;
        String configJson = redisTemplate.opsForValue().get(cacheKey);
        
        if (configJson == null || configJson.isEmpty()) {
            configJson = loadDefaultSetting();
            redisTemplate.opsForValue().set(cacheKey, configJson, CACHE_EXPIRE, TimeUnit.MINUTES);
        }
        
        return parseConfig(configJson);
    }

    /**
     * 解析配置JSON字符串
     * 使用fastjson进行反序列化处理
     */
    private SystemSetting parseConfig(String configJson) {
        // 使用默认反序列化配置
        return JSON.parseObject(configJson, SystemSetting.class);
    }

    /**
     * 加载默认系统配置
     * 当缓存不存在时的兜底方案
     */
    private String loadDefaultSetting() {
        SystemSetting defaultSetting = new SystemSetting();
        defaultSetting.setAuthProvider(new AuthProvider());
        return JSON.toJSONString(defaultSetting);
    }

    /**
     * 更新商户配置
     * 同步更新缓存和持久化存储
     */
    public void updateConfig(String merchantId, SystemSetting newSetting) {
        String cacheKey = CONFIG_KEY_PREFIX + merchantId;
        String newJson = JSON.toJSONString(newSetting);
        
        redisTemplate.opsForValue().set(cacheKey, newJson, CACHE_EXPIRE, TimeUnit.MINUTES);
        // 实际业务中会同时写入数据库
    }

    /**
     * 系统配置实体类
     * 包含认证提供方等核心配置
     */
    public static class SystemSetting {
        private AuthProvider authProvider;

        public AuthProvider getAuthProvider() {
            return authProvider;
        }

        public void setAuthProvider(AuthProvider authProvider) {
            this.authProvider = authProvider;
        }
    }

    /**
     * 认证提供方配置
     * 包含认证组等基础信息
     */
    public static class AuthProvider {
        private String GROUP = "default_group";

        public String getGROUP() {
            return GROUP;
        }

        public void setGROUP(String GROUP) {
            this.GROUP = GROUP;
        }
    }
}