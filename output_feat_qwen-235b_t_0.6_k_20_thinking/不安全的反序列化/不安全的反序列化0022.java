package com.example.iot.controller;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    
    // 模拟设备状态存储
    private static final Map<String, DeviceStatus> deviceCache = new HashMap<>();

    @PostMapping("/update")
    public String handleDeviceUpdate(@RequestBody String payload) {
        try {
            // 漏洞点：直接反序列化不可信输入
            DeviceData data = JSON.parseObject(payload, DeviceData.class);
            
            // 更新设备状态
            DeviceStatus status = new DeviceStatus();
            status.setDeviceId(data.getDeviceId());
            status.setTimestamp(System.currentTimeMillis());
            status.setMetrics(data.getMetrics());
            
            deviceCache.put(data.getDeviceId(), status);
            
            return "{\\"status\\":\\"success\\"}";
        } catch (Exception e) {
            return String.format("{\\"error\\":\\"%s\\"}", e.getMessage());
        }
    }
    
    // 恶意攻击者可能构造的特殊类
    public static class MaliciousClass {
        static {
            // 实际攻击中可能包含任意代码执行
            System.out.println("[ATTACK] Code execution through deserialization");
        }
    }
    
    // 设备数据模型
    public static class DeviceData {
        private String deviceId;
        private Map<String, Object> metrics;
        
        // Getters & Setters
        public String getDeviceId() { return deviceId; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
        
        public Map<String, Object> getMetrics() { return metrics; }
        public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }
    }
    
    public static class DeviceStatus {
        private String deviceId;
        private long timestamp;
        private Map<String, Object> metrics;
        
        // Getters & Setters
        public String getDeviceId() { return deviceId; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
        
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        
        public Map<String, Object> getMetrics() { return metrics; }
        public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }
    }
}