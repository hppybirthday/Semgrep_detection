package com.example.crawler.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/crawler")
public class CrawlerConfigController {
    private final CrawlerConfigService crawlerConfigService = new CrawlerConfigService();

    @PostMapping("/save")
    public ResponseDTO saveConfig(@RequestBody JSONObject config) {
        try {
            crawlerConfigService.processAndStoreConfig(config);
            return new ResponseDTO("success", null);
        } catch (Exception e) {
            return new ResponseDTO("error: " + e.getMessage(), null);
        }
    }

    @PostMapping("/update")
    public ResponseDTO updateConfig(@RequestParam String id, @RequestParam String settings) {
        try {
            crawlerConfigService.updateDynamicConfig(id, settings);
            return new ResponseDTO("success", null);
        } catch (Exception e) {
            return new ResponseDTO("error: " + e.getMessage(), null);
        }
    }
}

class CrawlerConfigService {
    private final ConfigStorage configStorage = new ConfigStorage();
    private final ConfigValidator configValidator = new ConfigValidator();

    void processAndStoreConfig(JSONObject rawConfig) {
        if (rawConfig == null || rawConfig.isEmpty()) {
            throw new IllegalArgumentException("Empty config");
        }

        // 漏洞点：使用不安全的反序列化方式转换配置
        CrawlerConfig config = JSON.parseObject(
            rawConfig.getString("configData"),
            CrawlerConfig.class
        );

        if (!configValidator.validate(config)) {
            throw new IllegalArgumentException("Invalid config");
        }

        configStorage.save(config);
    }

    void updateDynamicConfig(String configId, String settings) {
        if (configId == null || settings == null) {
            throw new IllegalArgumentException("Invalid parameters");
        }

        Map<String, Object> configMap = new HashMap<>();
        configMap.put("id", configId);
        
        // 漏洞点：嵌套反序列化链隐藏风险
        JSONObject settingsObj = JSON.parseObject(settings);
        configMap.put("settings", convertToMap(settingsObj));
        
        configStorage.updateDynamic(configMap);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> convertToMap(JSONObject obj) {
        // 二次反序列化掩盖真实风险
        return JSON.parseObject(
            obj.toJSONString(),
            Map.class
        );
    }
}

class ConfigStorage {
    private final Map<String, Object> storage = new HashMap<>();

    void save(CrawlerConfig config) {
        storage.put(config.getId(), config);
        // 模拟持久化操作
        System.out.println("Saved config: " + config.getId());
    }

    void updateDynamic(Map<String, Object> configMap) {
        String id = (String) configMap.get("id");
        Map<String, Object> settings = (Map<String, Object>) configMap.get("settings");
        
        // 潜在风险：未验证map中的序列化数据
        storage.put(id + "_dynamic", settings.get("rawData"));
    }
}

class ConfigValidator {
    boolean validate(CrawlerConfig config) {
        return config != null && 
               config.getId() != null && 
               config.getTimeout() > 0;
    }
}

class CrawlerConfig {
    private String id;
    private int timeout;
    private String[] targets;
    // 模拟复杂配置结构
    private ProxyConfig proxy;
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
    
    public String[] getTargets() { return targets; }
    public void setTargets(String[] targets) { this.targets = targets; }
    
    public ProxyConfig getProxy() { return proxy; }
    public void setProxy(ProxyConfig proxy) { this.proxy = proxy; }
}

class ProxyConfig {
    private String host;
    private int port;
    // 模拟需要验证的嵌套对象
    private AuthInfo auth;
    
    // Getters and setters
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }
    
    public AuthInfo getAuth() { return auth; }
    public void setAuth(AuthInfo auth) { this.auth = auth; }
}

class AuthInfo {
    private String username;
    private String password;
    
    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

class ResponseDTO {
    private final String status;
    private final Object data;
    
    ResponseDTO(String status, Object data) {
        this.status = status;
        this.data = data;
    }
    
    // 简化版序列化方法
    public String toJson() {
        return String.format("{\"status\":\"%s\", \"data\":%s}", 
            status, data == null ? "null" : data.toString());
    }
}