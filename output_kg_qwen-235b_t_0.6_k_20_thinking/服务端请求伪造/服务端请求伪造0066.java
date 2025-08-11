package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @PostMapping
    public String createTask(@RequestBody TaskRequest request) {
        return taskService.createTask(request.getCallbackUrl());
    }
}

class TaskRequest {
    private String callbackUrl;

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }
}

@Service
class TaskService {
    private final RestTemplate restTemplate;

    public TaskService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String createTask(String callbackUrl) {
        // 模拟任务处理完成后触发回调
        Map<String, String> payload = new HashMap<>();
        payload.put("status", "completed");
        
        // 存在SSRF漏洞的关键点：直接使用用户输入的URL发起请求
        String response = restTemplate.postForObject(callbackUrl, payload, String.class);
        
        return "Callback response: " + response;
    }
}