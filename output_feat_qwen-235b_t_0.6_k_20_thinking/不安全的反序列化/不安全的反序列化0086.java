package com.example.demo;

import com.alibaba.fastjson.JSON;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class VulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}

@RestController
@RequestMapping("/device")
class DeviceController {
    
    @PostMapping("/update")
    public String processDeviceData(@RequestParam String payload) {
        try {
            // 模拟快速原型开发中对设备数据的反序列化处理
            DeviceConfig config = JSON.parseObject(payload, DeviceConfig.class);
            
            // 模拟设备状态同步逻辑
            System.out.println(String.format("Updating device %s to firmware %s",
                config.getDeviceId(), config.getFirmwareVersion()));
                
            // 模拟将配置写入Redis的不安全操作
            String serialized = JSON.toJSONString(config);
            System.out.println("Storing in Redis: " + serialized);
            
            return "OK";
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

/**
 * IoT设备配置类 - 包含敏感操作注解
 * 模拟实际设备配置对象的复杂结构
 */
class DeviceConfig implements Serializable {
    private String deviceId;
    private String firmwareVersion;
    private Map<String, Object> settings = new HashMap<>();
    
    // 模拟设备关联的业务分类注解（攻击面入口）
    @SuppressWarnings("unused")
    private final String LAST_ASSOCIATED_CATEGORIES_ANNO = "com.alibaba.fastjson.annotation.JSONField";
    
    // 模拟设备认证令牌的敏感字段
    @SuppressWarnings("unused")
    private transient String authToken;
    
    // 模拟设备状态同步的回调方法
    public void syncStatus() {
        System.out.println("Syncing device status...");
    }

    // Getter和Setter
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    
    public String getFirmwareVersion() { return firmwareVersion; }
    public void setFirmwareVersion(String firmwareVersion) { this.firmwareVersion = firmwareVersion; }
    
    public Map<String, Object> getSettings() { return settings; }
    public void setSettings(Map<String, Object> settings) { this.settings = settings; }
}