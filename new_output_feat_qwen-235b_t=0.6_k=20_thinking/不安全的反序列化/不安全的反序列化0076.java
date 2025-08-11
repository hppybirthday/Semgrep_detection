package com.example.ml.service;

import com.example.ml.model.DynamicDataSourceModel;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Service
public class ModelService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public ModelService(RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    public DynamicDataSourceModel loadModel(String modelKey) throws IOException {
        DynamicDataSourceModel model = getCacheModel(modelKey);
        if (model == null) {
            model = loadFromFile("/tmp/object");
            cacheModel(modelKey, model);
        }
        return model;
    }

    private DynamicDataSourceModel getCacheModel(String key) {
        return (DynamicDataSourceModel) redisTemplate.opsForValue().get("model:" + key);
    }

    private void cacheModel(String key, DynamicDataSourceModel model) {
        redisTemplate.opsForValue().set("model:" + key, model, 30, java.util.concurrent.TimeUnit.SECONDS);
    }

    private DynamicDataSourceModel loadFromFile(String path) throws IOException {
        byte[] data = Files.readAllBytes(new File(path).toPath());
        return objectMapper.readValue(data, DynamicDataSourceModel.class);
    }
}

package com.example.ml.model;

import com.alibaba.fastjson.JSON;
import java.io.Serializable;

public class DynamicDataSourceModel implements Serializable {
    private static final long serialVersionUID = 1L;
    private String config;

    public DynamicDataSourceModel() {
        this.config = "{}";
    }

    public void initConfig() {
        try {
            Object obj = JSON.parseObject(config, Object.class);
            if (obj instanceof Map) {
                ((Map<?, ?>) obj).forEach((k, v) -> System.out.println(k + ":" + v));
            }
        } catch (Exception e) {
            // Silent catch to hide errors
        }
    }

    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        initConfig();
    }
}

package com.example.ml.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(Object.class));
        template.setEnableDefaultTyping(true);
        template.afterPropertiesSet();
        return template;
    }
}

// FastJSON dependency in pom.xml:
// <dependency>
//     <groupId>com.alibaba</groupId>
//     <artifactId>fastjson</artifactId>
//     <version>1.2.83</version>
// </dependency>