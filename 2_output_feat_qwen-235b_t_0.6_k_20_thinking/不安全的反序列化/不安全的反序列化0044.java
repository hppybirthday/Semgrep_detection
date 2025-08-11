package com.iot.device.controller;

import com.alibaba.fastjson.JSON;
import com.iot.device.model.DeviceConfig;
import com.iot.device.service.ConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/mock/dlglong")
public class DeviceConfigController {
    @Autowired
    private ConfigService configService;

    @PostMapping("/immediateSaveRow")
    public String saveConfig(@RequestBody Map<String, Object> payload, HttpServletRequest request) {
        // 从请求头获取设备ID
        String deviceId = request.getHeader("X-Device-ID");
        if (deviceId == null || deviceId.isEmpty()) {
            return "Device ID required";
        }

        // 解析配置数据
        Map<String, Object> configData = parseConfigData(payload);
        
        // 验证配置格式（仅检查必要字段）
        if (!isValidConfigFormat(configData)) {
            return "Invalid config format";
        }

        // 保存设备配置
        configService.saveConfiguration(deviceId, configData);
        return "Config saved";
    }

    private Map<String, Object> parseConfigData(Map<String, Object> payload) {
        // 从payload提取配置信息
        Object configObj = payload.get("config");
        if (configObj instanceof String) {
            // 尝试反序列化JSON字符串
            return JSON.parseObject((String) configObj, Map.class);
        } else if (configObj instanceof Map) {
            return (Map<String, Object>) configObj;
        }
        return new HashMap<>();
    }

    private boolean isValidConfigFormat(Map<String, Object> config) {
        // 检查必要字段是否存在
        return config.containsKey("version") && 
               config.containsKey("settings");
    }
}

// --- Service Layer ---
package com.iot.device.service;

import com.iot.device.model.DeviceConfig;
import com.iot.device.repository.ConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ConfigService {
    @Autowired
    private ConfigRepository configRepository;

    public void saveConfiguration(String deviceId, Map<String, Object> configData) {
        // 将Map转换为设备配置对象
        DeviceConfig deviceConfig = convertToConfig(configData);
        
        // 保存到持久化存储
        configRepository.save(deviceId, deviceConfig);
    }

    private DeviceConfig convertToConfig(Map<String, Object> configMap) {
        // 使用FastJSON进行类型转换
        return (DeviceConfig) JSON.parseObject(
            JSON.toJSONString(configMap), 
            DeviceConfig.class
        );
    }
}

// --- Model Layer ---
package com.iot.device.model;

import java.util.Map;

public class DeviceConfig {
    private String version;
    private Map<String, Object> settings;
    private String encryptionKey;

    // Getters and setters
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public Map<String, Object> getSettings() { return settings; }
    public void setSettings(Map<String, Object> settings) { this.settings = settings; }

    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
}

// --- Repository Layer ---
package com.iot.device.repository;

import com.iot.device.model.DeviceConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import javax.annotation.Resource;

@Repository
public class ConfigRepository {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public void save(String deviceId, DeviceConfig config) {
        // 使用Redis存储设备配置
        redisTemplate.opsForValue().set("device:config:" + deviceId, config);
    }

    public DeviceConfig find(String deviceId) {
        return (DeviceConfig) redisTemplate.opsForValue().get("device:config:" + deviceId);
    }
}