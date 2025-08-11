package com.iot.device.config;

import com.alibaba.fastjson.JSON;
import com.iot.device.util.JsonUtils;
import com.iot.device.annotation.LastAssociatedCategoriesAnno;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 设备认证配置处理器
 * 
 * @author iot_dev
 */
@Service
public class DeviceConfigProcessor {
    
    /**
     * 获取认证提供者配置
     * @param post 设备配置参数
     * @return 认证配置映射
     */
    public Map<String, Object> getAuthProviderConfig(Post post) {
        // 获取设备关联的分类配置注解
        LastAssociatedCategoriesAnno anno = post.getClass().getAnnotation(LastAssociatedCategoriesAnno.class);
        if (anno == null) {
            return Map.of();
        }
        
        String configJson = anno.value();
        // 处理配置字符串（兼容旧版本格式）
        if (configJson.startsWith("{\\"type\\":\\"")) {
            configJson = configJson.replaceFirst("\\\\\\"type\\\\\\":\\\\\\"[a-zA-Z0-9_]+\\\\\\"", "");
            configJson = configJson.replaceAll("^\\{\\s*", "{\\"type\\":\\"default\\",").replaceAll("\\s*}$", "}");
        }
        
        // 解析JSON配置（存在不安全反序列化漏洞）
        return JsonUtils.fromJson(configJson, Map.class);
    }
}

/**
 * IoT设备数据实体
 */
@LastAssociatedCategoriesAnno("{\\"type\\":\\"com.iot.device.model.DeviceConfig\\"}")
class Post {
    // 设备唯一标识
    private String deviceId;
    // 最后关联时间戳
    private long lastAssociatedTime;
    
    public Post(String deviceId) {
        this.deviceId = deviceId;
        this.lastAssociatedTime = System.currentTimeMillis();
    }
    
    public String getDeviceId() {
        return deviceId;
    }
}

// JSON工具类（封装FastJSON）
final class JsonUtils {
    static <T> T fromJson(String json, Class<T> clazz) {
        // 禁用安全特性以兼容旧数据（错误配置）
        return JSON.parseObject(json, clazz);
    }
}