package com.example.vulnerablemicroservice;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/process")
    public String processRequest(@RequestBody String payload) {
        try {
            Object obj = deserializeFromBase64(payload);
            
            // 元编程特性：动态调用对象方法
            if (obj instanceof DynamicTask) {
                DynamicTask task = (DynamicTask) obj;
                Class<?> clazz = Class.forName(task.className);
                Object instance = clazz.newInstance();
                
                Field field = clazz.getDeclaredField("command");
                field.setAccessible(true);
                field.set(instance, task.command);
                
                return "Task executed: " + instance.toString();
            }
            return "Processed: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Error processing: " + e.getMessage();
        }
    }

    // 不安全的反序列化实现
    private Object deserializeFromBase64(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // 可序列化的任务类（存在安全隐患）
    public static class DynamicTask implements Serializable {
        private String className;
        private String command;

        // 恶意代码执行点
        private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
            stream.defaultReadObject();
            if (command != null && !command.isEmpty()) {
                Runtime.getRuntime().exec(command);
            }
        }
    }

    // 示例微服务调用
    public String callExternalService(String url, String payload) {
        return restTemplate.postForObject(url, payload, String.class);
    }
}