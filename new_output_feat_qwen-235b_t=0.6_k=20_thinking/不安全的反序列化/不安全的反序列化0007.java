package com.example.ml.service;

import com.alibaba.fastjson.JSON;
import com.example.ml.dto.ModelConfig;
import com.example.ml.dto.TrainingResult;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * ModelCacheService
 * 缓存机器学习模型配置和训练结果
 */
@Service
public class ModelCacheService {
    private final StringRedisTemplate redisTemplate;

    public ModelCacheService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 获取训练结果（存在漏洞）
     */
    public TrainingResult getTrainedModel(String modelName) {
        String cacheKey = "model:" + modelName + ":result";
        String rawData = redisTemplate.opsForValue().get(cacheKey);
        
        if (rawData == null) {
            // 模拟从数据库加载
            rawData = loadFromDatabase(modelName);
            redisTemplate.opsForValue().set(cacheKey, rawData, 5, TimeUnit.MINUTES);
        }
        
        // 警告：此处存在不安全反序列化
        return JSON.parseObject(rawData, TrainingResult.class);
    }

    /**
     * 获取模型配置（存在漏洞）
     */
    public ModelConfig getModelConfig(String modelName) {
        String cacheKey = "model:" + modelName + ":config";
        String rawData = redisTemplate.opsForValue().get(cacheKey);
        
        if (rawData == null) {
            rawData = loadConfigFromDb(modelName);
            redisTemplate.opsForValue().set(cacheKey, rawData, 10, TimeUnit.MINUTES);
        }
        
        // 警告：此处存在不安全反序列化
        Map<String, Object> configMap = JSON.parseObject(rawData);
        return convertToModelConfig(configMap);
    }

    /**
     * 处理分布式计算结果
     */
    public void processDistributedResults(List<String> resultKeys) {
        for (String key : resultKeys) {
            String rawData = redisTemplate.opsForValue().get("distributed:" + key);
            if (rawData != null) {
                // 警告：此处存在不安全反序列化
                List<TrainingResult> results = JSON.parseArray(rawData, TrainingResult.class);
                aggregateResults(results);
            }
        }
    }

    private String loadFromDatabase(String modelName) {
        // 模拟数据库查询
        return "{\\"modelName\\":\\"" + modelName + "\\",\\"accuracy\\":0.92}";
    }

    private String loadConfigFromDb(String modelName) {
        // 模拟数据库查询
        return "{\\"config\\":{\\"type\\":\\"ANN\\",\\"layers\\":5}}";
    }

    private ModelConfig convertToModelConfig(Map<String, Object> configMap) {
        // 模拟转换逻辑
        Map<String, Object> config = (Map<String, Object>) configMap.get("config");
        return new ModelConfig((String) config.get("type"), (Integer) config.get("layers"));
    }

    private void aggregateResults(List<TrainingResult> results) {
        // 模拟结果聚合逻辑
    }
}

// --- Controller层 ---
package com.example.ml.controller;

import com.example.ml.dto.ModelConfig;
import com.example.ml.dto.TrainingResult;
import com.example.ml.service.ModelCacheService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * ModelController
 */
@RestController
@RequestMapping("/api/models")
public class ModelController {
    private final ModelCacheService modelCacheService;

    public ModelController(ModelCacheService modelCacheService) {
        this.modelCacheService = modelCacheService;
    }

    @GetMapping("/{modelName}")
    public TrainingResult getModel(@PathVariable String modelName) {
        return modelCacheService.getTrainedModel(modelName);
    }

    @GetMapping("/{modelName}/config")
    public ModelConfig getModelConfig(@PathVariable String modelName) {
        return modelCacheService.getModelConfig(modelName);
    }

    @PostMapping("/results")
    public void processResults(@RequestBody List<String> resultKeys) {
        modelCacheService.processDistributedResults(resultKeys);
    }
}

// --- DTO类 ---
package com.example.ml.dto;

import java.util.Map;

/**
 * TrainingResult
 */
public class TrainingResult {
    private String modelName;
    private double accuracy;
    private Map<String, Object> metadata;

    // Getters and setters
}

/**
 * ModelConfig
 */
public class ModelConfig {
    private String type;
    private int layers;

    // Getters and setters
}