package com.example.ml.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ModelService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public ModelService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = new ObjectMapper();
        // 危险的反序列化配置
        this.objectMapper.enable(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY);
    }

    public String updateModelParams(String modelKey, Map<String, Object> params) {
        // 从Redis加载现有模型参数
        Object cached = redisTemplate.opsForValue().get("model:" + modelKey);
        if (cached == null) {
            return "Model not found";
        }

        try {
            // 漏洞点：不安全的反序列化
            ModelParams modelParams = deserializeModelParams((byte[]) cached);
            
            // 合并新参数（模拟机器学习参数更新）
            modelParams.getHyperParameters().putAll(params);
            
            // 持久化到Redis
            redisTemplate.opsForValue().set("model:" + modelKey, 
                objectMapper.writeValueAsBytes(modelParams));
                
            return "Parameters updated successfully";
        } catch (Exception e) {
            return "Error updating parameters: " + e.getMessage();
        }
    }

    // 存在漏洞的反序列化方法
    private ModelParams deserializeModelParams(byte[] data) throws JsonProcessingException {
        // 直接反序列化字节数组，未验证目标类
        return objectMapper.readValue(data, ModelParams.class);
    }
}

// 模型参数类（需要实现序列化接口）
class ModelParams implements java.io.Serializable {
    private Map<String, Object> hyperParameters;
    private String modelName;
    private int version;

    // Getters and setters
    public Map<String, Object> getHyperParameters() { return hyperParameters; }
    public void setHyperParameters(Map<String, Object> hyperParameters) { 
        this.hyperParameters = hyperParameters; 
    }
    public String getModelName() { return modelName; }
    public void setModelName(String modelName) { this.modelName = modelName; }
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }
}

// 控制器层
package com.example.ml.controller;

import com.example.ml.service.ModelService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/ml")
public class ModelController {
    private final ModelService modelService;

    public ModelController(ModelService modelService) {
        this.modelService = modelService;
    }

    @PostMapping("/updateModel/{modelKey}")
    public String updateModel(@PathVariable String modelKey, @RequestBody Map<String, Object> params) {
        // 恶意参数可能包含反序列化攻击载荷
        return modelService.updateModelParams(modelKey, params);
    }
}