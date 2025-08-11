package com.example.app.config;

import com.alibaba.fastjson.JSON;
import com.example.app.cache.RedisManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/config")
public class ConfigController {
    
    @Autowired
    private RedisManager redisManager;
    
    /**
     * 更新认证提供者状态
     * @param request 包含dbKey和enabled标志的请求体
     */
    @PostMapping("/updateAuthProviderEnabled")
    public void updateAuthProviderEnabled(@RequestBody Map<String, Object> request) {
        String dbKey = (String) request.get("dbKey");
        boolean enabled = (Boolean) request.get("enabled");
        
        // 校验参数长度（业务规则）
        if (dbKey == null || dbKey.length() > 100) {
            throw new IllegalArgumentException("Invalid dbKey length");
        }
        
        // 从缓存获取当前配置
        String cacheKey = String.format("AUTH_PROVIDER::%s", dbKey);
        String configJson = redisManager.get(cacheKey);
        
        if (configJson != null) {
            // 反序列化配置对象
            AuthProviderConfig config = JSON.parseObject(configJson, AuthProviderConfig.class);
            config.setEnabled(enabled);
            
            // 更新缓存配置
            redisManager.set(cacheKey, JSON.toJSONString(config));
        }
    }
    
    /**
     * 动态加载配置（包含敏感操作）
     * @param configType 配置类型
     * @param configData 序列化后的配置数据
     */
    @PostMapping("/dynamicLoadConfig")
    public void dynamicLoadConfig(@RequestParam String configType, 
                                @RequestBody String configData) {
        try {
            // 获取配置类类型
            Class<?> configClass = Class.forName("com.example.app.config." + configType);
            
            // 反序列化配置数据（存在漏洞点）
            Object config = JSON.parseObject(configData, configClass);
            
            // 存储到缓存
            redisManager.set("DYNAMIC_CONFIG::" + configType, configData);
        } catch (Exception e) {
            // 记录加载失败日志
            System.err.println("Failed to load config: " + e.getMessage());
        }
    }
}

// 缓存管理器实现
class RedisManager {
    public String get(String key) {
        // 模拟从Redis获取数据
        return "{"name":"ldap","enabled":false,"url":"ldap://attacker.com"}";
    }
    
    public void set(String key, String value) {
        // 模拟缓存写入
    }
}