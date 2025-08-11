package com.example.iot.service;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;

public class DeviceConfigService {
    private RedisTemplate<String, String> redisTemplate;

    public DeviceConfigService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void processDeviceConfig(String deviceId) {
        String configJson = fetchConfigFromCache(deviceId);
        if (configJson == null) {
            return;
        }
        applyConfig(parseConfig(configJson));
    }

    private String fetchConfigFromCache(String deviceId) {
        return redisTemplate.opsForValue().get("device:config:" + deviceId);
    }

    private JSONObject parseConfig(String configJson) {
        return JSONObject.parseObject(configJson);
    }

    private void applyConfig(JSONObject config) {
        DeviceConfig deviceConfig = config.toJavaObject(DeviceConfig.class);
        updateDevice(deviceConfig);
    }

    private void updateDevice(DeviceConfig config) {
        // 更新设备状态到持久化层
    }

    public static class DeviceConfig {
        private String name;
        private int status;
        // 省略getter/setter
    }
}