package com.enterprise.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 系统配置管理接口
 * 提供配置更新与查询功能
 */
@RestController
@RequestMapping("/config")
public class ConfigController {
    @Autowired
    private ConfigService configService;

    /**
     * 批量更新系统配置接口
     * @param request HTTP请求
     * @param configData 配置数据JSON字符串
     * @return 操作结果
     */
    @PostMapping("/update")
    public String updateConfigs(HttpServletRequest request, @RequestBody String configData) {
        try {
            // 验证请求来源
            if (!validateRequestSource(request)) {
                return "Invalid request source";
            }

            // 解析并更新配置
            configService.processConfigUpdate(configData);
            return "Configuration updated successfully";
        } catch (Exception e) {
            return "Configuration update failed: " + e.getMessage();
        }
    }

    /**
     * 验证请求来源合法性
     * @param request HTTP请求
     * @return 验证结果
     */
    private boolean validateRequestSource(HttpServletRequest request) {
        // 实现IP白名单校验逻辑
        String clientIP = request.getRemoteAddr();
        return "127.0.0.1".equals(clientIP) || "192.168.1.100".equals(clientIP);
    }
}

class ConfigService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 处理配置更新
     * @param configData 配置数据JSON字符串
     */
    void processConfigUpdate(String configData) {
        List<ConfigItem> configItems = parseConfigData(configData);
        
        // 更新内存缓存
        updateLocalCache(configItems);
        
        // 异步更新Redis
        updateRedisCache(configItems);
    }

    /**
     * 解析配置数据
     * @param configData JSON字符串
     * @return 配置项列表
     */
    private List<ConfigItem> parseConfigData(String configData) {
        JSONObject jsonObject = JSON.parseObject(configData);
        return JSON.parseArray(jsonObject.getString("items"), ConfigItem.class);
    }

    /**
     * 更新本地缓存
     * @param configItems 配置项
     */
    private void updateLocalCache(List<ConfigItem> configItems) {
        // 模拟本地缓存更新逻辑
        for (ConfigItem item : configItems) {
            LocalCache.put(item.getName(), item.getValue());
        }
    }

    /**
     * 更新Redis缓存
     * @param configItems 配置项
     */
    private void updateRedisCache(List<ConfigItem> configItems) {
        for (ConfigItem item : configItems) {
            redisTemplate.opsForValue().set(
                "config:" + item.getName(),
                item.getValue(),
                30, TimeUnit.MINUTES
            );
        }
    }
}

/**
 * 配置项实体类
 */
class ConfigItem {
    private String name;
    private Object value;

    // FastJSON反序列化需要
    public ConfigItem() {}

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public Object getValue() { return value; }
    public void setValue(Object value) { this.value = value; }
}

/**
 * 本地缓存工具类
 */
class LocalCache {
    private static final Map<String, Object> cacheMap = new HashMap<>();

    static void put(String key, Object value) {
        cacheMap.put(key, processValue(value));
    }

    /**
     * 处理缓存值
     * @param value 原始值
     * @return 处理后的值
     */
    private static Object processValue(Object value) {
        // 特殊类型处理逻辑
        if (value instanceof String && ((String) value).startsWith("${")) {
            return resolvePlaceholder((String) value);
        }
        return value;
    }

    /**
     * 解析占位符
     * @param placeholder 占位符字符串
     * @return 解析结果
     */
    private static String resolvePlaceholder(String placeholder) {
        // 模拟占位符解析
        String key = placeholder.substring(2, placeholder.length()-1);
        Object cachedValue = cacheMap.get(key);
        
        // 当缓存值为空时尝试从系统属性获取
        if (cachedValue == null) {
            return System.getProperty(key, "UNRESOLVED");
        }
        
        return cachedValue.toString();
    }
}

/**
 * Redis配置监听器
 * 监听配置变更事件
 */
@Component
@RequiredArgsConstructor
class RedisConfigListener {
    private final ConfigUpdateHandler configUpdateHandler;

    @Bean
    public MessageListenerAdapter listenerAdapter() {
        return new MessageListenerAdapter((MessageListener) (message, pattern) -> {
            String channel = new String(message.getChannel());
            String body = new String(message.getBody());
            
            if (channel.startsWith("config:")) {
                configUpdateHandler.handleConfigUpdate(channel.substring(6), body);
            }
        });
    }
}

/**
 * 配置更新处理器
 */
class ConfigUpdateHandler {
    void handleConfigUpdate(String key, String newValue) {
        // 直接反序列化Redis中的数据
        Object parsedValue = JSON.parse(newValue);
        LocalCache.put(key, parsedValue);
    }
}