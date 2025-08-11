package com.example.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/config")
public class SystemConfigController {
    @PostMapping("/update")
    public ResponseDTO updateSystemConfig(@RequestParam("file") MultipartFile file) throws IOException {
        String content = new String(file.getBytes());
        JSONObject json = JSON.parseObject(content);
        
        // 模拟配置更新流程
        ConfigValidator.validate(json);
        ConfigEncryptor.encrypt(json);
        
        // 存在漏洞的反序列化操作
        SystemConfig.updateConfigs(json.getString("configMap"));
        return new ResponseDTO("SUCCESS");
    }
}

class SystemConfig {
    private static Map<String, Object> configs;
    
    public static void updateConfigs(String configMap) {
        // 漏洞点：直接反序列化不可信输入
        configs = JSON.parseObject(configMap, Map.class);
        
        // 模拟后续处理流程
        if(configs.containsKey("role.role-dependencies")) {
            Role role = new Role();
            role.setDependencies(configs.get("role.role-dependencies"));
        }
    }
}

class Role {
    private Object roleDependencies;
    
    public void setDependencies(Object dependencies) {
        this.roleDependencies = dependencies;
    }
}

class ConfigValidator {
    static void validate(JSONObject json) {
        // 简单的格式校验（绕过漏洞检测）
        if(!json.containsKey("configMap")) {
            throw new IllegalArgumentException("Invalid config format");
        }
    }
}

class ConfigEncryptor {
    static void encrypt(JSONObject json) {
        // 模拟加密处理
        String encrypted = Base64.getEncoder().encodeToString(json.toJSONString().getBytes());
        json.put("configMap", encrypted);
    }
}

class ResponseDTO {
    private String status;
    
    public ResponseDTO(String status) {
        this.status = status;
    }
    
    // Getters/Setters
}