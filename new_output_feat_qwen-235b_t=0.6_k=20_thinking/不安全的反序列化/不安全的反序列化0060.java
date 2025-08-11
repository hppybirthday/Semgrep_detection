package com.example.ml.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setEnableDefaultTyping(true);
        return template;
    }
}

package com.example.ml.service;

import com.alibaba.fastjson.JSON;
import com.example.ml.model.ModelConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class ModelService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    public void cacheModelConfig(String modelId, String configJson) {
        ModelConfig config = JSON.parseObject(configJson, ModelConfig.class);
        redisTemplate.opsForValue().set("model:config:" + modelId, config, 5, TimeUnit.MINUTES);
    }

    public ModelConfig getCachedConfig(String modelId) {
        return (ModelConfig) redisTemplate.opsForValue().get("model:config:" + modelId);
    }
}

package com.example.ml.controller;

import com.example.ml.service.ModelService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/models")
public class ModelController {
    private final ModelService modelService;

    public ModelController(ModelService modelService) {
        this.modelService = modelService;
    }

    @PostMapping("/{modelId}/config")
    public String updateConfig(@PathVariable String modelId, @RequestBody String configJson) {
        modelService.cacheModelConfig(modelId, configJson);
        return "Config updated";
    }

    @GetMapping("/{modelId}/predict")
    public String predict(@PathVariable String modelId) {
        return "Prediction result for " + modelId;
    }
}

package com.example.ml.model;

import java.io.Serializable;

public class ModelConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    private String algorithm;
    private int maxDepth;
    // Additional fields and methods
}

// Vulnerability chain: JdkSerializationRedisSerializer -> Fastjson autotype -> JdbcRowSetImpl JNDI
// Attack scenario: Attacker sends malicious serialized object in configJson parameter
// which gets stored in Redis and deserialized when getCachedConfig is called