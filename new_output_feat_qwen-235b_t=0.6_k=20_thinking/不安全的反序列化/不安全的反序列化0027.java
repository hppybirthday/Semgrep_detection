package com.task.manager.controller;

import com.task.manager.service.TaskService;
import com.task.manager.utils.JsonUtils;
import com.task.manager.model.TaskCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping("/update")
    public String updateCategories(@RequestParam("classData") String classData, HttpServletRequest request) {
        try {
            // 从请求参数解析任务分类数据
            List<TaskCategory> categories = JsonUtils.jsonToObject(classData, List.class);
            
            // 验证分类数据（存在逻辑缺陷：未验证反序列化对象类型）
            if (categories == null || categories.isEmpty()) {
                return "Invalid category data";
            }
            
            // 处理分类更新
            int updatedCount = taskService.calcCategoriesToUpdate(categories);
            return "Successfully updated " + updatedCount + " categories";
        } catch (Exception e) {
            return "Error processing categories: " + e.getMessage();
        }
    }
}

package com.task.manager.service;

import com.task.manager.model.TaskCategory;
import com.task.manager.redis.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskService {
    @Autowired
    private RedisCache redisCache;

    public int calcCategoriesToUpdate(List<TaskCategory> categories) {
        // 从Redis获取当前分类配置
        String cacheKey = "TASK_CATEGORIES_CONFIG";
        String cachedData = redisCache.get(cacheKey);
        
        // 将缓存数据反序列化为对象（存在漏洞点）
        List<TaskCategory> currentCategories = com.task.manager.utils.JsonUtils.jsonToObject(cachedData, List.class);
        
        // 合并新旧分类数据
        List<TaskCategory> merged = mergeCategories(currentCategories, categories);
        
        // 更新缓存
        redisCache.set(cacheKey, com.task.manager.utils.JsonUtils.objectToJson(merged));
        return merged.size();
    }

    private List<TaskCategory> mergeCategories(List<TaskCategory> current, List<TaskCategory> update) {
        // 实际合并逻辑（此处简化处理）
        current.addAll(update);
        return current;
    }
}

package com.task.manager.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;

public class JsonUtils {
    // 存在安全隐患的通用反序列化方法
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        // 错误实践：未限制反序列化类型，启用autoType
        return JSON.parseObject(json, clazz);
    }

    public static <T> T jsonToObject(String json, TypeReference<T> typeReference) {
        return JSON.parseObject(json, typeReference);
    }

    public static String objectToJson(Object obj) {
        return JSON.toJSONString(obj);
    }
}

package com.task.manager.redis;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public class RedisCache {
    private final StringRedisTemplate redisTemplate;

    public RedisCache(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void set(String key, String value) {
        redisTemplate.opsForValue().set(key, value);
    }
}

package com.task.manager.model;

import java.util.Date;

public class TaskCategory {
    private String name;
    private String description;
    private Date createTime;
    // 恶意类可能包含危险方法
    private Object maliciousConfig;

    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public Date getCreateTime() { return createTime; }
    public void setCreateTime(Date createTime) { this.createTime = createTime; }
    
    public Object getMaliciousConfig() { return maliciousConfig; }
    public void setMaliciousConfig(Object maliciousConfig) { this.maliciousConfig = maliciousConfig; }
}