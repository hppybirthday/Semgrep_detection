package com.example.tasksystem;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@SpringBootApplication
public class TaskManagementApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagementApplication.class, args);
    }

    @RestController
    @RequestMapping("/tasks")
    public static class TaskController {
        @Autowired
        private TaskService taskService;

        @PostMapping
        public ResponseEntity<String> createTask(@RequestBody TaskDTO dto) {
            try {
                taskService.createTask(dto.getDescription(), dto.getCallbackUrl());
                return ResponseEntity.ok("Task created");
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Error: " + e.getMessage());
            }
        }
    }

    @Service
    public static class TaskService {
        @Autowired
        private ExternalService externalService;

        private final Map<String, String> taskMap = new HashMap<>();
        private final ExecutorService executor = Executors.newCachedThreadPool();

        public void createTask(String description, String callbackUrl) {
            String taskId = "task_" + System.currentTimeMillis();
            taskMap.put(taskId, description);
            
            // 异步触发回调
            executor.submit(() -> {
                try {
                    externalService.notifyCompletion(callbackUrl, taskId);
                } catch (Exception e) {
                    System.err.println("Callback failed: " + e.getMessage());
                }
            });
        }
    }

    @Service
    public static class ExternalService {
        private final RestTemplate restTemplate = new RestTemplate();

        public void notifyCompletion(String callbackUrl, String taskId) {
            // 漏洞点：直接使用用户输入的URL发起请求
            String payload = String.format("{\\"taskId\\":\\"%s\\"}", taskId);
            ResponseEntity<String> response = restTemplate.postForEntity(
                callbackUrl, 
                payload, 
                String.class
            );
            System.out.println("Callback response: " + response.getStatusCode());
        }
    }

    public static class TaskDTO {
        private String description;
        private String callbackUrl;
        
        // Getters and setters
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }\        public String getCallbackUrl() { return callbackUrl; }
        public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
    }
}