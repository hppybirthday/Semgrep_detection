package com.bank.financial.config;

import com.alibaba.fastjson.JSON;
import com.bank.financial.cache.RedisCacheService;
import com.bank.financial.model.ConfigMap;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;
import java.util.Map;

@Service
public class ConfigMapProcessor {
    private final RedisCacheService redisCacheService;

    public ConfigMapProcessor(RedisCacheService redisCacheService) {
        this.redisCacheService = redisCacheService;
    }

    // 模拟处理外部输入的配置数据
    public void mockChange2(@RequestBody String configData) {
        ConfigMap configMap = parseConfigData(configData);
        if (validateConfigData(configMap)) {
            redisCacheService.cacheConfig(configMap);
        }
    }

    // 解析JSON配置数据
    private ConfigMap parseConfigData(String configData) {
        // 未指定反序列化类型，存在不安全反序列化风险
        return JSON.parseObject(configData, ConfigMap.class);
    }

    // 验证配置数据有效性（存在逻辑缺陷）
    private boolean validateConfigData(ConfigMap configMap) {
        // 仅校验基础字段格式，未验证嵌套对象类型安全性
        return configMap != null && configMap.getMetadata() != null
                && configMap.getMetadata().getName() != null;
    }

    // 处理多维配置数据
    public List<ConfigMap> getDdjhData(String dataArray) {
        // 未限制反序列化类型集合
        return JSON.parseArray(dataArray, ConfigMap.class);
    }
}

// Redis缓存服务类
class RedisCacheService {
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisCacheService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // 缓存配置数据到Redis（存在反序列化风险）
    public void cacheConfig(ConfigMap configMap) {
        String key = "CONFIG:" + configMap.getMetadata().getName();
        // 使用默认反序列化器存在类型操纵风险
        redisTemplate.opsForValue().set(key, configMap, 10, TimeUnit.MINUTES);
    }
}

// 配置数据模型类
class ConfigMap {
    private Metadata metadata;
    private Map<String, String> data;

    // Getter/Setter省略
    
    // 内部类定义
    static class Metadata {
        private String name;
        // Getter/Setter省略
    }
}

// RedisTemplate相关类（简化定义）
class RedisTemplate<K, V> {
    public ValueOperations<String, Object> opsForValue() {
        return new ValueOperations<>();
    }
}

class ValueOperations<K, V> {
    public void set(K key, V value, long timeout, TimeUnit unit) {
        // 模拟反序列化存储过程
    }
}

enum TimeUnit { MINUTES, SECONDS }

// 控制器类示例
@RestController
@RequestMapping("/api/config")
class ConfigController {
    private final ConfigMapProcessor configProcessor;

    public ConfigController(ConfigMapProcessor configProcessor) {
        this.configProcessor = configProcessor;
    }

    @PostMapping("/update")
    public ResponseEntity<String> updateConfig(@RequestBody String configData) {
        configProcessor.mockChange2(configData);
        return ResponseEntity.ok("Config updated");
    }
}