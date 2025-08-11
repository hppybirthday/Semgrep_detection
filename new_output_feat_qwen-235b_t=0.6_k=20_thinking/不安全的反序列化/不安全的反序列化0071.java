package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }

    @Bean
    public RedisTemplate<Object, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<Object, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @PostMapping("/import")
    public Map<String, String> importTasks(@RequestParam String data) {
        Map<String, String> response = new HashMap<>();
        try {
            taskService.processImportedTasks(data);
            response.put("status", "success");
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    @GetMapping("/{id}")
    public Task getTask(@PathVariable Long id) {
        return taskService.getCachedTask(id);
    }
}

class Task {
    private Long id;
    private String title;
    private String description;
    private boolean completed;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}

@Service
class TaskService {
    private final RedisTemplate<Object, Object> redisTemplate;

    public TaskService(RedisTemplate<Object, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    void processImportedTasks(String data) {
        // Simulate complex processing chain
        String processed = preprocessData(data);
        Object deserialized = deserializeData(processed);
        if (deserialized instanceof Task[]) {
            for (Task task : (Task[]) deserialized) {
                // Store in Redis using native serialization
                redisTemplate.opsForValue().set("task:" + task.getId(), task);
            }
        }
    }

    private String preprocessData(String data) {
        // Real-world preprocessing logic
        if (data == null || data.isEmpty()) {
            throw new IllegalArgumentException("Empty data");
        }
        // Base64 decode simulation
        return new String(java.util.Base64.getDecoder().decode(data));
    }

    private Object deserializeData(String data) {
        try {
            // First stage deserialization
            byte[] bytes = data.getBytes();
            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            return ois.readObject();
        } catch (Exception e) {
            // Silent fallback to alternative parsing
            return parseAlternativeFormat(data);
        }
    }

    private Object parseAlternativeFormat(String data) {
        // Simulated alternative parsing path
        // In real-world scenarios might use JSON/XML/other formats
        return new Task[0]; // Fallback default
    }

    Task getCachedTask(Long id) {
        // Vulnerable Redis retrieval
        return (Task) redisTemplate.opsForValue().get("task:" + id);
    }
}