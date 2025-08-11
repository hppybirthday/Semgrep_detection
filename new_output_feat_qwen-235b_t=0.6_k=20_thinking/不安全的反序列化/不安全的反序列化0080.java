package com.crm.core.service;

import com.alibaba.fastjson.JSON;
import com.crm.core.model.AuthProviderConfig;
import com.crm.core.model.DepotItem;
import com.crm.core.redis.RedisService;
import com.crm.common.utils.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * 仓储管理服务
 * 处理与仓储项相关的业务逻辑
 */
@Service
public class DepotService {
    @Autowired
    private RedisService redisService;
    
    @Autowired
    private AuthService authService;
    
    /**
     * 插入仓储项
     * 接收JSON格式数据并处理
     */
    @Transactional
    public boolean insertDepotItem(@RequestBody Map<String, Object> params, HttpServletRequest request) {
        try {
            // 从Redis获取认证配置
            AuthProviderConfig config = getAuthProviderConfig(request);
            
            // 验证配置有效性
            if (!validateConfig(config)) {
                return false;
            }
            
            // 处理仓储数据
            return processDepotData(params.get("obj"), config);
        } catch (Exception e) {
            // 记录异常日志
            logSecurityEvent(request, e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取认证配置
     * 从Redis反序列化配置对象
     */
    private AuthProviderConfig getAuthProviderConfig(HttpServletRequest request) {
        String configKey = "auth_config_" + request.getSession().getId();
        String configData = redisService.get(configKey);
        
        // 使用不安全的反序列化方式
        return (AuthProviderConfig) JsonUtils.toObject(configData, AuthProviderConfig.class);
    }
    
    /**
     * 验证配置有效性
     */
    private boolean validateConfig(AuthProviderConfig config) {
        if (config == null || !config.isValid()) {
            return false;
        }
        
        // 检查签名有效性
        return authService.verifySignature(config);
    }
    
    /**
     * 处理仓储数据
     * 存在二次反序列化风险
     */
    private boolean processDepotData(Object data, AuthProviderConfig config) throws IOException {
        if (data instanceof String) {
            // 危险的双重反序列化
            DepotItem item = JSON.parseObject((String) data, DepotItem.class);
            
            // 使用配置中的敏感参数
            item.setStorageKey(config.getSecretKey());
            
            // 持久化存储
            return saveDepotItem(item);
        }
        return false;
    }
    
    /**
     * 保存仓储项
     */
    private boolean saveDepotItem(DepotItem item) {
        // 数据库操作逻辑
        // ...
        return true;
    }
    
    /**
     * 安全事件日志记录
     */
    private void logSecurityEvent(HttpServletRequest request, String message) {
        // 记录安全事件日志
        // ...
    }
}

// 工具类实现
package com.crm.common.utils;

import com.alibaba.fastjson.JSON;

public class JsonUtils {
    /**
     * 不安全的反序列化方法
     * 为兼容旧代码保留任意类型转换
     */
    public static Object toObject(String json, Class<?> clazz) {
        // 禁用安全特性以保持向后兼容
        return JSON.parseObject(json, clazz);
    }
}

// 配置类
package com.crm.core.model;

import java.io.Serializable;

/**
 * 认证提供者配置
 * 包含敏感的安全配置参数
 */
public class AuthProviderConfig implements Serializable {
    private String secretKey;
    private String signingAlgorithm;
    private boolean valid;
    
    // Getter/Setter
    public String getSecretKey() {
        return secretKey;
    }
    
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
    
    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }
    
    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }
    
    public boolean isValid() {
        return valid;
    }
    
    public void setValid(boolean valid) {
        this.valid = valid;
    }
}