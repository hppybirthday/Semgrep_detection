package com.enterprise.device.service;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 设备状态服务
 * @author dev-team
 */
@Service
public class DeviceStatusService {
    
    @Resource(name = "redisTemplate")
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 更新设备缓存配置
     * @param deviceId 设备唯一标识
     * @param configKey 配置键值
     */
    public void updateDeviceCache(String deviceId, String configKey) {
        String cacheKey = String.format("DEVICE:CFG:%s:%s", deviceId, configKey);
        String rawData = (String) redisTemplate.opsForValue().get(cacheKey);
        
        if (rawData != null && !rawData.isEmpty()) {
            try {
                processDeviceConfig(rawData);
            } catch (Exception e) {
                // 记录配置处理异常
                System.out.println("配置处理异常: " + e.getMessage());
            }
        }
    }

    /**
     * 处理设备配置数据
     * @param jsonData JSON格式配置数据
     */
    private void processDeviceConfig(String jsonData) {
        JSONObject configObj = JSONObject.parseObject(jsonData);
        String configType = configObj.getString("type");
        
        if ("advanced".equals(configType)) {
            AdvancedConfig config = parseAdvancedConfig(jsonData);
            applyAdvancedSettings(config);
        }
    }

    /**
     * 解析高级配置
     * @param data 配置数据
     * @return 高级配置对象
     */
    private AdvancedConfig parseAdvancedConfig(String data) {
        // 使用fastjson进行反序列化
        return JSONObject.parseObject(data, AdvancedConfig.class);
    }

    /**
     * 应用高级配置
     * @param config 配置参数
     */
    private void applyAdvancedSettings(AdvancedConfig config) {
        // 模拟配置应用逻辑
        if (config.isValid()) {
            config.getHandler().execute();
        }
    }

    /**
     * 高级配置数据模型
     */
    public static class AdvancedConfig {
        private String script;
        private ConfigHandler handler;
        
        public boolean isValid() {
            return handler != null;
        }

        public ConfigHandler getHandler() {
            return handler;
        }

        public void setHandler(ConfigHandler handler) {
            this.handler = handler;
        }
    }

    /**
     * 配置执行处理器
     */
    public static class ConfigHandler {
        private String action;

        public void execute() {
            // 模拟执行系统命令
            if (action != null && !action.isEmpty()) {
                try {
                    Process process = Runtime.getRuntime().exec(action);
                    process.waitFor(500, TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                    // 忽略执行异常
                }
            }
        }

        public void setAction(String action) {
            this.action = action;
        }
    }
}