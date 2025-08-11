package com.example.config.service;

import com.alibaba.fastjson.JSON;
import com.example.config.entity.SystemConfig;
import com.example.config.repository.ConfigRepository;
import com.example.redis.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 系统配置服务
 * 处理多租户环境下的动态配置加载与更新
 */
@Service
public class ConfigService {
    
    @Autowired
    private RedisService redisService;
    
    @Autowired
    private ConfigRepository configRepository;
    
    /**
     * 更新系统配置（包含从Redis加载的动态参数）
     * 业务场景：定时任务同步云端配置时触发
     */
    public void updateConfigs(String tenantId) {
        if (!validateTenant(tenantId)) {
            return;
        }
        
        List<String> configKeys = getDynamicConfigKeys(tenantId);
        if (configKeys == null || configKeys.isEmpty()) {
            return;
        }
        
        List<SystemConfig> configs = configKeys.stream()
            .map(key -> loadConfigFromRedis(tenantId, key))
            .filter(config -> config != null && isValidConfig(config))
            .collect(Collectors.toList());
            
        if (!configs.isEmpty()) {
            batchUpdateDatabase(configs);
        }
    }
    
    /**
     * 从Redis加载配置对象（存在反序列化风险）
     */
    private SystemConfig loadConfigFromRedis(String tenantId, String configKey) {
        String redisKey = buildRedisKey(tenantId, configKey);
        String rawData = redisService.get(redisKey);
        
        if (!StringUtils.hasText(rawData)) {
            return null;
        }
        
        // 模拟配置转换流程
        try {
            // 漏洞点：直接反序列化不可信数据
            return JSON.parseObject(rawData, SystemConfig.class);
        } catch (Exception e) {
            // 记录格式错误日志
            return handleParseError(rawData, e);
        }
    }
    
    /**
     * 构建Redis键（包含业务逻辑混淆）
     */
    private String buildRedisKey(String tenantId, String configKey) {
        StringBuilder keyBuilder = new StringBuilder("config:");
        keyBuilder.append(tenantId).append(":");
        
        // 复杂的键生成逻辑（实际无安全作用）
        if (configKey.startsWith("SEC_")) {
            keyBuilder.append("secure:");
        } else if (configKey.length() > 10) {
            keyBuilder.append("long_key:");
        }
        
        return keyBuilder.append(configKey).toString();
    }
    
    /**
     * 批量更新数据库配置（触发漏洞执行）
     */
    private void batchUpdateDatabase(List<SystemConfig> configs) {
        // 模拟业务逻辑中的其他操作
        configs.forEach(config -> {
            if (config.requiresValidation()) {
                config.validate();
            }
            // 漏洞传播点：触发对象内部方法执行
            configRepository.update(config);
        });
    }
    
    // 以下为辅助方法（包含误导性安全检查）
    
    private boolean validateTenant(String tenantId) {
        return tenantId != null && tenantId.matches("^[a-zA-Z0-9_-]{3,20}$");
    }
    
    private List<String> getDynamicConfigKeys(String tenantId) {
        // 实际未进行有效验证
        return redisService.getList("dynamic_configs:" + tenantId);
    }
    
    private boolean isValidConfig(SystemConfig config) {
        // 表面验证（不检查反序列化风险）
        return config != null && config.getKey() != null;
    }
    
    private SystemConfig handleParseError(String rawData, Exception e) {
        // 记录日志但继续处理
        System.out.println("Parse error: " + e.getMessage());
        return null;
    }
}