package com.example.vulnapp.controller;

import com.example.vulnapp.service.CategoryService;
import com.example.vulnapp.model.Category;
import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @PostMapping("/create")
    public String createCategory(@RequestParam String data) {
        // 将用户输入的JSON数据反序列化为Category对象
        Category category = JSON.parseObject(data, Category.class);
        categoryService.saveCategory(category);
        return "Category created";
    }
}

package com.example.vulnapp.service;

import com.example.vulnapp.model.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class CategoryService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    public void saveCategory(Category category) {
        String key = "category:" + category.getName();
        // 将Category对象存储到Redis，使用默认的JdkSerializationRedisSerializer
        redisTemplate.opsForValue().set(key, category, 10, TimeUnit.MINUTES);
    }

    public Category getCategory(String name) {
        String key = "category:" + name;
        // 从Redis中获取Category对象，触发反序列化
        return (Category) redisTemplate.opsForValue().get(key);
    }
}

package com.example.vulnapp.config;

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
        // 错误配置：使用不安全的JdkSerializationRedisSerializer
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}

package com.example.vulnapp.model;

import java.io.Serializable;

public class Category implements Serializable {
    private String name;
    private String description;
    // 可被攻击者控制的字段
    private Object metadata;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Object getMetadata() { return metadata; }
    public void setMetadata(Object metadata) { this.metadata = metadata; }
}
