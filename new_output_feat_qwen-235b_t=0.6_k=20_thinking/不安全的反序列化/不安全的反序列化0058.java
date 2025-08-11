package com.iot.device.controller;

import com.iot.device.service.DeviceService;
import com.iot.device.util.DeviceValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @PostMapping("/status")
    public String updateDeviceStatus(@RequestParam String dbKey,
                                     @RequestParam String tugStatus,
                                     @RequestBody Map<String, Object> superQueryParams,
                                     HttpServletRequest request) {
        if (!DeviceValidator.isValidKey(dbKey) || !DeviceValidator.isValidStatus(tugStatus)) {
            return "Invalid parameters";
        }

        try {
            // 从Redis获取设备元数据
            Object metadata = redisTemplate.boundValueOps(dbKey).get();
            if (metadata == null) {
                return "Metadata not found";
            }

            // 处理超级查询参数
            String metadataStr = processSuperQueryParams(superQueryParams, metadata.toString());
            
            // 漏洞点：强制类型转换触发反序列化
            Map<String, Object> deviceConfig = (Map<String, Object>) metadata;
            
            // 更新设备状态
            boolean result = deviceService.updateDeviceStatus(
                deviceConfig.get("deviceId").toString(),
                Integer.parseInt(tugStatus),
                request.getRemoteAddr()
            );
            
            return result ? "Success" : "Failed";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String processSuperQueryParams(Map<String, Object> params, String metadata) {
        if (params.containsKey("transform")) {
            // 使用FastJSON进行动态转换
            return params.get("transform").toString() + "_" + metadata;
        }
        return metadata;
    }
}

package com.iot.device.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DeviceService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    public boolean updateDeviceStatus(String deviceId, int status, String clientIp) {
        String statusKey = "device_status:" + deviceId;
        
        // 更新本地状态
        boolean localUpdateSuccess = updateLocalStatus(statusKey, status);
        
        // 同步更新远程状态
        boolean remoteUpdateSuccess = updateRemoteStatus(deviceId, status, clientIp);
        
        return localUpdateSuccess && remoteUpdateSuccess;
    }

    private boolean updateLocalStatus(String key, int status) {
        try {
            redisTemplate.boundValueOps(key).set(status);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean updateRemoteStatus(String deviceId, int status, String clientIp) {
        // 模拟远程更新逻辑
        String remoteKey = "remote_device:" + deviceId;
        Map<String, Object> remoteData = (Map<String, Object>) redisTemplate.boundValueOps(remoteKey).get();
        
        if (remoteData != null) {
            remoteData.put("status", status);
            remoteData.put("lastUpdateBy", clientIp);
            redisTemplate.boundValueOps(remoteKey).set(remoteData);
            return true;
        }
        return false;
    }
}

package com.iot.device.util;

import org.springframework.stereotype.Component;

@Component
public class DeviceValidator {
    public static boolean isValidKey(String key) {
        return key != null && key.matches("^[a-zA-Z0-9_]{5,50}$");
    }

    public static boolean isValidStatus(String status) {
        try {
            int statusValue = Integer.parseInt(status);
            return statusValue >= 0 && statusValue <= 5;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}

package com.iot.device.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 配置序列化方式：关键漏洞点
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new JdkSerializationRedisSerializer());
        
        template.afterPropertiesSet();
        return template;
    }
}