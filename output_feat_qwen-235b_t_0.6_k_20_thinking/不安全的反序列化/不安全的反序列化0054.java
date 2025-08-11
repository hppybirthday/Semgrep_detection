package com.example.iot.device;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/device")
public class DeviceController {
    // 模拟设备状态存储
    private Map<String, DeviceConfig> deviceConfigs = new HashMap<>();

    @PostMapping("/update")
    public String updateDeviceConfig(@RequestBody byte[] encryptedData) {
        try {
            // 模拟解密过程（实际未实现）
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(encryptedData)) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) {
                    // 自定义黑名单过滤（存在缺陷）
                    String className = desc.getName();
                    if (className.contains("sun.rmi") || className.contains("com.sun.jndi")) {
                        throw new InvalidClassException("Forbidden class: " + className);
                    }
                    return super.resolveClass(desc);
                }
            };
            
            // 不安全的反序列化操作
            DeviceOperation operation = (DeviceOperation) ois.readObject();
            ois.close();
            
            // 执行设备操作
            if (operation.getType() == OperationType.UPDATE_CONFIG) {
                DeviceConfig config = operation.getDeviceConfig();
                deviceConfigs.put(config.getDeviceId(), config);
                return "Config updated for " + config.getDeviceId();
            }
            
            return "Operation executed successfully";
        } catch (Exception e) {
            // 防御式编程：记录日志但暴露详细错误
            System.err.println("Deserialization error: " + e.getMessage());
            return "Error processing request";
        }
    }

    // 模拟数据传输对象
    static class DeviceOperation implements Serializable {
        private OperationType type;
        private DeviceConfig deviceConfig;
        
        // Getters/Setters
        public OperationType getType() { return type; }
        public void setType(OperationType type) { this.type = type; }
        public DeviceConfig getDeviceConfig() { return deviceConfig; }
        public void setDeviceConfig(DeviceConfig deviceConfig) { this.deviceConfig = deviceConfig; }
    }

    enum OperationType { UPDATE_CONFIG, REBOOT }

    static class DeviceConfig implements Serializable {
        private String deviceId;
        private String configMap; // 存储JSON格式配置
        
        // Getters/Setters
        public String getDeviceId() { return deviceId; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
        public String getConfigMap() { return configMap; }
        public void setConfigMap(String configMap) { this.configMap = configMap; }
    }
}