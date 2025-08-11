package com.example.taskmanager;

import com.alibaba.fastjson.JSON;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

interface TaskStorage {
    void saveTask(Task task);
    Task getTask(String id);
}

@Component
class RedisTaskStorage implements TaskStorage {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public void saveTask(Task task) {
        redisTemplate.opsForValue().set("task:" + task.getId(), task);
    }

    @Override
    public Task getTask(String id) {
        return (Task) redisTemplate.opsForValue().get("task:" + id);
    }
}

class Task implements Serializable {
    private String id;
    private String name;
    private transient Map<String, Object> config = new HashMap<>();

    // Getters and setters
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    @Resource
    private TaskStorage taskStorage;

    @PostMapping("/update")
    public String updateTask(@RequestBody String requestBody) {
        // 漏洞点：不安全的反序列化
        Task task = JSON.parseObject(requestBody, Task.class);
        taskStorage.saveTask(task);
        return "Task updated";
    }

    @GetMapping("/{id}")
    public Task getTask(@PathVariable String id) {
        return taskStorage.getTask(id);
    }
}

@Configuration
class SecurityConfig {
    // 错误的安全配置：未限制Fastjson反序列化类型
    @Bean
    public FastJsonHttpMessageConverter fastJsonHttpMessageConverter() {
        return new FastJsonHttpMessageConverter();
    }
}