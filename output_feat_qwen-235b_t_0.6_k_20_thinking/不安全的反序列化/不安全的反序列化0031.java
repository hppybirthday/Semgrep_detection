package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import com.alibaba.fastjson.JSONObject;
import java.io.Serializable;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/mock/dlglong")
class MockController {
    private final RedisTemplate<String, Object> redisTemplate;

    public MockController(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @GetMapping("/change2")
    public String changeStatus(@RequestParam String tug_status) {
        // 漏洞点1：直接反序列化不可信参数
        JSONObject obj = JSONObject.parseObject(tug_status);
        String taskId = obj.getString("taskId");
        
        // 模拟业务逻辑
        String cacheKey = "task:" + taskId;
        TaskMetadata metadata = (TaskMetadata) redisTemplate.boundValueOps(cacheKey).get();
        
        return "Status changed for " + metadata.getName();
    }

    @PostMapping("/immediateSaveRow")
    public void saveRow(@RequestBody String jsonData) {
        // 漏洞点2：直接反序列化请求体
        JSONObject.parseObject(jsonData, TaskMetadata.class);
    }
}

// 自定义Redis配置
@Bean
class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        // 漏洞点3：RedisTemplate未配置安全反序列化策略
        template.setKeySerializer(new org.springframework.data.redis.serializer.StringRedisSerializer());
        template.setValueSerializer(new org.springframework.data.redis.serializer.JdkSerializationRedisSerializer());
        return template;
    }
}

// 业务实体类
class TaskMetadata implements Serializable {
    private String name;
    private String type;
    
    // Fastjson反序列化需要默认构造函数
    public TaskMetadata() {}
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

// 自定义反序列化配置类
class SafeDeserialization {
    // 错误实现的黑名单过滤
    protected Class<?> resolveClass(ObjectStreamClass desc) {
        String className = desc.getName();
        // 仅阻止已知危险类导致绕过
        if (className.contains("CommonsCollections")) {
            throw new SecurityException("Blocked: " + className);
        }
        return Class.forName(className); // 允许加载任意类
    }
}