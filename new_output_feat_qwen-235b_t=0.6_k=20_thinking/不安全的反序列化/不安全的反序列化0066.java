package com.example.app.config;

import com.alibaba.fastjson.JSON;
import com.example.app.service.AuthService;
import com.example.app.dto.AuthConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/config")
public class ConfigController {
    @Autowired
    private AuthService authService;

    @PostMapping("/update")
    public String updateConfig(@RequestBody String configData, HttpServletRequest request) {
        try {
            // 从请求头获取认证令牌（模拟鉴权流程）
            String token = request.getHeader("X-Auth-Token");
            if (!validateToken(token)) {
                return "Unauthorized";
            }

            // 调用服务层处理配置更新
            authService.updateAuthProviderEnabled(configData);
            return "Update Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private boolean validateToken(String token) {
        // 模拟令牌验证逻辑（实际可能调用其他服务）
        return token != null && token.startsWith("valid_");
    }
}

package com.example.app.service;

import com.alibaba.fastjson.JSON;
import com.example.app.config.CacheManager;
import com.example.app.dto.AuthConfig;
import com.example.app.model.Provider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthService {
    @Autowired
    private CacheManager cacheManager;

    public void updateAuthProviderEnabled(String configData) {
        try {
            // 关键漏洞点：直接反序列化用户输入
            AuthConfig config = JSON.parseObject(configData, AuthConfig.class);
            
            // 模拟配置处理流程
            Provider provider = loadProvider(config.getProviderId());
            if (provider == null) {
                throw new IllegalArgumentException("Invalid provider");
            }

            // 更新配置到缓存
            cacheManager.updateConfig(config);
            
            // 模拟日志记录（触发toString()可能导致延迟执行）
            if (config.toString().contains("malicious")) {
                Runtime.getRuntime().exec("calc"); // 模拟RCE触发点
            }
        } catch (Exception e) {
            // 记录异常但未处理安全风险
            System.err.println("Update failed: " + e.getMessage());
        }
    }

    private Provider loadProvider(String providerId) {
        // 模拟从数据库加载提供者信息
        return new Provider(providerId, "mock_provider_type");
    }
}

package com.example.app.config;

import com.example.app.dto.AuthConfig;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class CacheManager {
    private final Map<String, AuthConfig> configCache = new HashMap<>();

    public void updateConfig(AuthConfig config) {
        // 模拟缓存更新操作
        configCache.put(config.getProviderId(), config);
    }

    public AuthConfig getConfig(String providerId) {
        return configCache.get(providerId);
    }
}

package com.example.app.dto;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.Data;

import java.util.Map;

@Data
public class AuthConfig {
    private String providerId;
    private boolean enabled;
    private String configData;
    
    // 模拟复杂配置结构
    @JSONField(name = "extra_params")
    private Map<String, Object> extraParams;
    
    // 模拟toString()中的潜在危险操作
    @Override
    public String toString() {
        return "AuthConfig{" +
                "providerId='" + providerId + '\\'' +
                ", enabled=" + enabled +
                ", extraParamsSize=" + (extraParams != null ? extraParams.size() : 0) +
                '}';
    }
}

package com.example.app.model;

import lombok.Data;

@Data
public class Provider {
    private String id;
    private String type;

    public Provider(String id, String type) {
        this.id = id;
        this.type = type;
    }
}