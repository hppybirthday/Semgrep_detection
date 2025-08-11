package com.example.service;

import com.alibaba.fastjson.JSON;
import com.example.model.CacheKeyGenerator;
import com.example.util.RedisUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 用户配置服务类
 * 提供用户个性化配置的存储与解析功能
 */
@Service
public class UserConfigService {
    
    @Resource
    private RedisUtil redisUtil;

    /**
     * 存储并解析用户配置
     * @param configMap 请求参数映射
     */
    public void processUserConfig(@RequestBody Map<String, Object> configMap) {
        String dbKey = generateCacheKey(configMap);
        
        // 先尝试从缓存加载配置
        Object cachedConfig = redisUtil.get(dbKey);
        if (cachedConfig == null) {
            // 缓存未命中时解析原始配置
            cachedConfig = parseConfig(configMap.get("configData"));
            // 将解析结果写入缓存
            redisUtil.set(dbKey, cachedConfig, 300);
        }
        
        // 业务逻辑后续处理...
    }

    /**
     * 生成缓存键
     */
    private String generateCacheKey(Map<String, Object> configMap) {
        String userId = (String) configMap.get("userId");
        String configType = (String) configMap.get("configType");
        return CacheKeyGenerator.generate(userId, configType);
    }

    /**
     * 解析配置数据
     * @param configData JSON字符串
     */
    private Object parseConfig(Object configData) {
        // 校验输入格式（业务规则）
        if (!(configData instanceof String) || ((String) configData).length() < 5) {
            return new DefaultConfig();
        }
        
        // 使用fastjson进行反序列化
        return JSON.parseObject((String) configData);
    }

    /**
     * 默认配置类
     */
    private static class DefaultConfig {
        private String theme = "default";
        private boolean enableFeatureX = false;
    }
}