package com.example.taskmanager;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

// 任务实体类
abstract class Task {
    private String id;
    private String description;
    
    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }
    
    public abstract void execute();
    
    public String getId() { return id; }
    public String getDescription() { return description; }
}

// HTTP任务执行器
class HttpTaskExecutor extends Task {
    private String callbackUrl;
    private HttpClient httpClient;
    
    public HttpTaskExecutor(String id, String description, String callbackUrl) {
        super(id, description);
        this.callbackUrl = callbackUrl;
        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public void execute() {
        try {
            // 存在漏洞：直接使用用户提供的URL发起请求
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(callbackUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\\"taskId\\":\\"" + getId() + "\\"}"))
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Response status code: " + response.statusCode());
        } catch (Exception e) {
            System.err.println("Task execution failed: " + e.getMessage());
        }
    }
}

// 任务工厂
class TaskFactory {
    public static Task createTask(String type, String id, String description, String callbackUrl) {
        return new HttpTaskExecutor(id, description, callbackUrl);
    }
}

// 任务执行服务
class TaskExecutionService {
    private Map<String, Task> taskStore = new HashMap<>();
    
    public void registerTask(Task task) {
        taskStore.put(task.getId(), task);
    }
    
    public void executeTask(String taskId) {
        Task task = taskStore.get(taskId);
        if (task != null) {
            task.execute();
        } else {
            System.out.println("Task not found: " + taskId);
        }
    }
}

// 模拟任务管理系统入口
public class TaskManager {
    public static void main(String[] args) {
        TaskExecutionService taskService = new TaskExecutionService();
        
        // 用户创建任务时指定恶意URL
        Task task = TaskFactory.createTask(
            "http",
            "task001",
            "Process payment",
            "http://localhost:8080/admin/internal-api"  // SSRF攻击目标
        );
        
        taskService.registerTask(task);
        taskService.executeTask("task001");
    }
}