package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/tasks")
public class TaskManagerApplication {
    private static final Map<String, String> TASK_CALLBACKS = new HashMap<>();
    private static final RestTemplate restTemplate = new RestTemplate();

    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }

    @PostMapping
    public ResponseEntity<String> createTask(@RequestParam String id, @RequestParam String callbackUrl) {
        // 元编程特性：通过反射动态注册回调方法
        try {
            Method method = TaskManagerApplication.class.getMethod("executeCallback", String.class);
            TASK_CALLBACKS.put(id, callbackUrl);
            return ResponseEntity.ok("Task created with SSRF vulnerability");
        } catch (NoSuchMethodException e) {
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

    @GetMapping("/{taskId}")
    public ResponseEntity<String> completeTask(@PathVariable String taskId) {
        // 模拟任务完成时触发回调
        if (TASK_CALLBACKS.containsKey(taskId)) {
            String callbackUrl = TASK_CALLBACKS.get(taskId);
            
            // 存在漏洞的代码：直接使用用户提供的URL发起请求
            try {
                // 漏洞点：未验证目标URL安全性
                String response = restTemplate.getForObject(callbackUrl, String.class);
                return ResponseEntity.ok("Callback executed: " + response);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Callback failed: " + e.getMessage());
            }
        }
        return ResponseEntity.notFound().build();
    }

    // 元编程特性：动态执行方法
    public static void executeCallback(String taskId) {
        System.out.println("Executing callback for task: " + taskId);
    }

    // 漏洞利用示例：curl -X POST "http://localhost:8080/tasks?id=1&callbackUrl=http://localhost:8080/actuator/shutdown"
}
// 漏洞原理：用户可控制回调URL参数，服务器直接发起未经验证的请求，导致攻击者可通过特殊构造的URL访问内部资源