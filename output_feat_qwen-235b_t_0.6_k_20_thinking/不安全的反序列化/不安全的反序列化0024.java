package com.example.ml.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/models")
public class ModelConfigController {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @PostMapping("/train")
    public String handleModelTraining(@RequestBody String payload) {
        try {
            // 漏洞点：不安全的反序列化操作
            Map<String, Object> config = JSON.parseObject(
                payload,
                new TypeReference<Map<String, Object>>() {},
                Feature.SupportNonPublicField
            );
            
            // 模拟防御式编程的无效尝试
            if (config.containsKey("params") && config.get("params") instanceof String[]) {
                String[] params = (String[]) config.get("params");
                // 实际业务逻辑（此处为模拟）
                redisTemplate.opsForValue().set("model:params", params);
                return "Training started";
            }
            
            return "Invalid configuration";
            
        } catch (Exception e) {
            // 日志记录（防御式编程体现）
            System.err.println("Invalid model configuration: " + e.getMessage());
            return "Configuration error";
        }
    }

    // 模拟存在的危险反序列化辅助方法
    private Object convertValueSafely(String json) {
        // 错误实现：未限制反序列化类型
        return JSON.parseObject(
            json,
            Object.class,
            Feature.SupportNonPublicField
        );
    }
}