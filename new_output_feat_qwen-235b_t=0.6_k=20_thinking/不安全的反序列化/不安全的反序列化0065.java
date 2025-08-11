package com.mathsim.core.service;

import com.alibaba.fastjson.JSON;
import com.mathsim.core.entity.MathModelEntity;
import com.mathsim.core.redis.RedisMathModelCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class MathModelService {
    @Autowired
    private RedisMathModelCache redisMathModelCache;

    public MathModelEntity getMathModel(String modelId) {
        String cacheKey = "MATH_MODEL:" + modelId;
        String modelJson = redisMathModelCache.get(cacheKey);
        
        if (modelJson == null || modelJson.isEmpty()) {
            MathModelEntity entity = fetchFromDatabase(modelId);
            if (entity != null) {
                redisMathModelCache.set(cacheKey, JSON.toJSONString(entity), 5, TimeUnit.MINUTES);
            }
            return entity;
        }
        
        // 漏洞点：未指定反序列化类型白名单
        return JSON.parseObject(modelJson, MathModelEntity.class);
    }

    private MathModelEntity fetchFromDatabase(String modelId) {
        // 模拟数据库查询
        return new MathModelEntity(modelId, "LinearRegression", "{}", 1.0);
    }

    public void updateModelParameters(String modelId, String newParams) {
        MathModelEntity entity = getMathModel(modelId);
        if (entity != null) {
            entity.setParameters(newParams);
            String cacheKey = "MATH_MODEL:" + modelId;
            redisMathModelCache.set(cacheKey, JSON.toJSONString(entity), 5, TimeUnit.MINUTES);
        }
    }
}

// --- Redis配置类 ---
package com.mathsim.core.redis;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

@Component
public class RedisMathModelCache {
    @Resource(name = "redisTemplate")
    private RedisTemplate<String, String> redisTemplate;

    public String get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void set(String key, String value, long timeout, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, timeout, unit);
    }
}

// --- 实体类 ---
package com.mathsim.core.entity;

public class MathModelEntity {
    private String modelId;
    private String modelName;
    private String parameters;
    private double version;

    public MathModelEntity() {}

    public MathModelEntity(String modelId, String modelName, String parameters, double version) {
        this.modelId = modelId;
        this.modelName = modelName;
        this.parameters = parameters;
        this.version = version;
    }

    // Getters and Setters
    public String getModelId() { return modelId; }
    public void setModelId(String modelId) { this.modelId = modelId; }
    
    public String getModelName() { return modelName; }
    public void setModelName(String modelName) { this.modelName = modelName; }
    
    public String getParameters() { return parameters; }
    public void setParameters(String parameters) { this.parameters = parameters; }
    
    public double getVersion() { return version; }
    public void setVersion(double version) { this.version = version; }
}

// --- 控制器 ---
package com.mathsim.core.controller;

import com.mathsim.core.entity.MathModelEntity;
import com.mathsim.core.service.MathModelService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/models")
public class MathModelController {
    @Resource
    private MathModelService mathModelService;

    @GetMapping("/{modelId}")
    public MathModelEntity getModel(@PathVariable String modelId) {
        return mathModelService.getMathModel(modelId);
    }

    @PostMapping("/update")
    public String updateModel(@RequestParam String modelId, @RequestParam String newParams) {
        mathModelService.updateModelParameters(modelId, newParams);
        return "Updated";
    }
}