package com.example.taskmanager;

import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;

// 漏洞入口点：任务类允许序列化
class Task implements Serializable {
    private String id;
    private String description;
    private boolean completed;
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}

// 不安全的JSON工具类
class JsonUtils {
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        // 使用FastJSON默认反序列化配置（存在漏洞）
        return JSON.parseObject(json, clazz);
    }
}

@Service
class TaskService {
    @Autowired
    private StringRedisTemplate redisTemplate;

    public void saveTask(Task task) {
        String key = "task:" + task.getId();
        String json = JSON.toJSONString(task);
        redisTemplate.opsForValue().set(key, json);
    }

    public Task getTask(String taskId) {
        String key = "task:" + taskId;
        String json = redisTemplate.opsForValue().get(key);
        if (json != null) {
            // 存在漏洞的反序列化调用
            return JsonUtils.jsonToObject(json, Task.class);
        }
        return null;
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping
    public String createTask(@RequestBody Task task) {
        taskService.saveTask(task);
        return "Task saved";
    }

    @GetMapping("/{taskId}")
    public Task getTask(@PathVariable String taskId) {
        // 攻击面：通过Redis键值注入恶意JSON
        return taskService.getTask(taskId);
    }
}