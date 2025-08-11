package com.example.taskmanager.controller;

import com.example.taskmanager.dto.TaskDTO;
import com.example.taskmanager.service.TaskService;
import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Resource
    private TaskService taskService;

    @PostMapping("/create")
    public String createTask(@RequestParam String classData) {
        try {
            // 将用户输入的classData存储到Redis
            taskService.saveMaliciousData(classData);
            return "Task created successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

package com.example.taskmanager.service;

import com.alibaba.fastjson.JSON;
import com.example.taskmanager.dto.TaskDTO;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class TaskService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public void saveMaliciousData(String payload) {
        // 将用户输入的payload存储到Redis，未进行任何验证
        redisTemplate.opsForValue().set("malicious_payload", parseUserInput(payload));
    }

    private Object parseUserInput(String data) {
        // 使用FastJSON自动类型解析反序列化用户输入
        // 存在autoType漏洞风险
        return JSON.parseObject(data, Object.class);
    }

    public TaskDTO getTaskDetails() {
        // 从Redis取出数据并强制转换为TaskDTO
        // 如果Redis中存储的是恶意序列化对象，将导致类型转换错误或触发漏洞
        Object cachedData = redisTemplate.opsForValue().get("malicious_payload");
        if (cachedData instanceof TaskDTO) {
            return (TaskDTO) cachedData;
        }
        // 漏洞触发点：当cachedData是其他类型时，尝试二次解析
        return handleFallbackDeserialization(cachedData.toString());
    }

    private TaskDTO handleFallbackDeserialization(String data) {
        // 二次使用FastJSON解析字符串
        // 攻击者可通过构造特殊JSON结构触发反序列化漏洞
        return JSON.parseObject(data, TaskDTO.class);
    }
}

package com.example.taskmanager.dto;

import lombok.Data;

@Data
public class TaskDTO {
    private String taskId;
    private String taskName;
    private String description;
}

package com.example.taskmanager.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 使用Jackson序列化器，但允许反序列化任意类型
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
        
        return template;
    }
}