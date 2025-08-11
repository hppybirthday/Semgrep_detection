package com.example.mlapp.controller;

import com.example.mlapp.service.ModelService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/ml")
public class ModelTrainingController {
    @Resource
    private ModelService modelService;

    @PostMapping("/train")
    public void startTraining(@RequestParam String classData) {
        modelService.submitForProcessing(classData);
    }
}

package com.example.mlapp.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.*;
import java.util.Base64;

@Service
public class ModelService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public void submitForProcessing(String classData) {
        try {
            // 解码并直接反序列化用户输入，触发漏洞
            byte[] data = Base64.getDecoder().decode(classData);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                Object model = ois.readObject();
                // 异步处理：存储到Redis队列
                redisTemplate.opsForList().leftPush("ml:processing:queue", model);
            }
        } catch (Exception e) {
            // 忽略异常
        }
    }
}

package com.example.mlapp.processor;

import com.example.mlapp.service.ModelResultStorage;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class DistributedModelProcessor {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    @Resource
    private ModelResultStorage resultStorage;

    @Scheduled(fixedRate = 5000)
    public void process() {
        // 从Redis获取反序列化后的对象
        Object task = redisTemplate.opsForList().leftPop("ml:processing:queue");
        if (task != null) {
            // 业务逻辑处理
            resultStorage.saveProcessedResult(task.hashCode(), task.toString());
        }
    }
}

package com.example.mlapp.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class ModelResultStorage {
    private final Map<Integer, String> storage = new HashMap<>();

    public void saveProcessedResult(int key, String result) {
        storage.put(key, result);
    }
}