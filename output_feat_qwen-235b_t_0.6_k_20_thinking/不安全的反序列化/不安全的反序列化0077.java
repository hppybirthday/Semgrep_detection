package com.example.mathmodelling.cache;

import com.alibaba.fastjson.JSON;
import com.example.mathmodelling.model.SimulationConfiguration;

public class RedisAndLocalCache {
    private RedisCache redisCache; // 假设已实现的Redis操作类

    public RedisAndLocalCache(RedisCache redisCache) {
        this.redisCache = redisCache;
    }

    public <T> T get(String key, Class<T> clazz) {
        // 漏洞点：直接反序列化不可信数据
        String rawData = redisCache.get(key);
        return JSON.parseObject(rawData, clazz); // 不安全的反序列化
    }
}

package com.example.mathmodelling.service;

import com.example.mathmodelling.cache.RedisAndLocalCache;
import com.example.mathmodelling.model.SimulationConfiguration;
import org.springframework.stereotype.Service;

@Service
public class SimulationService {
    private RedisAndLocalCache cache;

    public SimulationService(RedisAndLocalCache cache) {
        this.cache = cache;
    }

    public void processSimulation(String configKey) {
        // 从缓存加载配置
        SimulationConfiguration config = cache.get(configKey, SimulationConfiguration.class);
        // 使用配置进行数学建模计算
        System.out.println("Processing simulation with step size: " + config.getStepSize());
    }
}

package com.example.mathmodelling.controller;

import com.example.mathmodelling.service.SimulationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/simulations")
public class SimulationController {
    private SimulationService simulationService;

    public SimulationController(SimulationService simulationService) {
        this.simulationService = simulationService;
    }

    @PostMapping("/run")
    public String runSimulation(@RequestParam String configKey) {
        // 漏洞触发点：用户控制的缓存键
        simulationService.processSimulation(configKey);
        return "Simulation started";
    }
}

package com.example.mathmodelling.model;

import java.io.Serializable;

public class SimulationConfiguration implements Serializable {
    private double stepSize;
    private int maxIterations;

    // Getters and setters
    public double getStepSize() { return stepSize; }
    public void setStepSize(double stepSize) { this.stepSize = stepSize; }
    public int getMaxIterations() { return maxIterations; }
    public void setMaxIterations(int maxIterations) { this.maxIterations = maxIterations; }
}

// 模拟Redis操作类
class RedisCache {
    // 简化实现，实际应连接Redis
    public String get(String key) {
        // 模拟从缓存获取JSON数据
        return "{\\"stepSize\\":0.01,\\"maxIterations\\":1000}"; // 恶意JSON可替换此处
    }
}