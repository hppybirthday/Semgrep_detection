package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class ConfigController {
    // 模拟企业级配置处理
    @PostMapping("/submitConfig")
    public ResponseEntity<String> processConfig(@RequestBody ConfigMap configMap) {
        try {
            // 危险操作：直接反序列化不可信的JSON数据
            // 使用元编程特性动态解析配置
            Map<String, Object> configData = JSON.parseObject(configMap.getData(), Map.class);
            
            // 模拟敏感操作：使用反射调用配置中的动态方法
            if (configData.containsKey("handler")) {
                Object handler = configData.get("handler");
                Class<?> clazz = Class.forName(handler.toString());
                Object instance = clazz.newInstance();
                
                // 模拟执行任意方法（元编程核心）
                java.lang.reflect.Method method = clazz.getMethod("toString");
                method.invoke(instance);
            }
            
            return ResponseEntity.ok("Config processed successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing config: " + e.getMessage());
        }
    }
}

// 模拟Kubernetes ConfigMap结构
class ConfigMap {
    private Metadata metadata;
    private String data; // 恶意数据注入点
    
    // Getters and setters
    public Metadata getMetadata() { return metadata; }
    public void setMetadata(Metadata metadata) { this.metadata = metadata; }
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
}

class Metadata {
    private String name;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}