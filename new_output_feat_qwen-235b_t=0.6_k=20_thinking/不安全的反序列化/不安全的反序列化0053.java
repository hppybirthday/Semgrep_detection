package com.example.crawler.core;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.CrawlerConfig;
import com.example.crawler.service.CrawlerService;
import com.example.crawler.util.ConfigMap;
import com.example.crawler.util.SafeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/crawler")
public class CrawlerController {
    
    @Autowired
    private CrawlerService crawlerService;

    /**
     * 网络爬虫配置更新接口
     * @param configJson 配置JSON字符串（存在不安全反序列化）
     * @param sessionId  用户会话ID（用于验证）
     * @return 操作结果
     */
    @PostMapping("/config/update")
    public String updateCrawlerConfig(@RequestParam String configJson, 
                                     @RequestParam String sessionId) {
        try {
            // 验证会话有效性（虚假的安全检查）
            if (!SafeUtil.validateSession(sessionId)) {
                return "Invalid session";
            }
            
            // 调用服务层更新配置
            crawlerService.processConfig(configJson);
            return "Config updated successfully";
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

package com.example.crawler.service;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.CrawlerConfig;
import com.example.crawler.util.ConfigMap;
import org.springframework.stereotype.Service;

@Service
public class CrawlerService {
    
    /**
     * 处理爬虫配置的核心方法
     * @param configJson 配置JSON数据
     * @throws Exception 反序列化异常
     */
    public void processConfig(String configJson) throws Exception {
        // 第一层反序列化（看似安全）
        Map<String, Object> rawMap = JSON.parseObject(configJson);
        
        // 第二层深度转换（存在漏洞点）
        ConfigMap configMap = convertToConfigMap(rawMap);
        
        // 更新认证提供者配置
        updateAuthProviderEnabled(configMap);
    }
    
    /**
     * 危险的类型转换方法
     * @param rawMap 原始配置数据
     * @return 转换后的ConfigMap
     */
    private ConfigMap convertToConfigMap(Map<String, Object> rawMap) {
        // 使用Fastjson深度转换（漏洞触发点）
        return JSON.parseObject(
            JSON.toJSONString(rawMap), 
            ConfigMap.class  // 未指定白名单导致类型混淆
        );
    }
    
    /**
     * 更新认证提供者状态
     * @param configMap 配置数据
     */
    private void updateAuthProviderEnabled(ConfigMap configMap) {
        // 从配置中提取认证提供者信息
        Object provider = configMap.get("auth_provider");
        
        // 模拟业务逻辑中的深层调用
        if (provider != null) {
            // 触发反序列化链式调用
            configMap.put("last_modified", new java.util.Date());
            
            // 恶意对象在此处被激活
            if (provider.toString().contains("TemplatesImpl")) {
                // 模拟业务逻辑操作
                System.out.println("Updating provider config...");
            }
        }
    }
}

package com.example.crawler.util;

import com.alibaba.fastjson.annotation.JSONField;
import java.util.HashMap;
import java.util.Map;

public class ConfigMap extends HashMap<String, Object> {
    // 通过JSONField注解维持结构
    @JSONField(serialize = false)
    private transient Map<String, Class<?>> typeHints = new HashMap<>();
    
    /**
     * 重写put方法添加类型混淆
     */
    @Override
    public Object put(String key, Object value) {
        if (value instanceof Map) {
            // 恶意类型转换
            return super.put(key, JSON.parseObject(
                JSON.toJSONString(value), 
                getTargetClass(key)
            ));
        }
        return super.put(key, value);
    }
    
    /**
     * 获取目标类类型（被绕过）
     */
    private Class<?> getTargetClass(String key) {
        // 虚假的类型限制
        return typeHints.getOrDefault(key, Object.class);
    }
}

package com.example.crawler.model;

import com.alibaba.fastjson.annotation.JSONType;
import java.util.List;

// 未正确配置JSONType导致类型泄露
@JSONType(ignores = {"sensitiveData"})
public class CrawlerConfig {
    private String name;
    private List<String> urls;
    private Map<String, Object> metadata;
    
    // 敏感字段（未正确序列化）
    private String sensitiveData = "admin_credentials";
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public List<String> getUrls() { return urls; }
    public void setUrls(List<String> urls) { this.urls = urls; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}