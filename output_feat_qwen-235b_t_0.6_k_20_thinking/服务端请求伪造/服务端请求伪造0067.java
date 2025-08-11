package com.example.taskmanager;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

// 领域模型
public class Task {
    private String id;
    private String title;
    private String thumbnailUrl;
    
    public Task(String id, String title, String thumbnailUrl) {
        this.id = id;
        this.title = title;
        this.thumbnailUrl = thumbnailUrl;
    }

    // 漏洞点：直接返回用户提供的URL
    public String getThumbnailUrl() {
        return thumbnailUrl;
    }
}

// 应用服务
public class TaskService {
    private TaskRepository taskRepository;

    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public CompletableFuture<Task> getTaskDetails(String taskId, String thumbnailOverride) {
        return taskRepository.findById(taskId)
            .thenApply(task -> {
                // 漏洞点：允许覆盖缩略图URL且未校验
                if (thumbnailOverride != null && !thumbnailOverride.isEmpty()) {
                    task = new Task(task.getId(), task.getTitle(), thumbnailOverride);
                }
                return task;
            });
    }
}

// 基础设施
public class HttpImageClient {
    private HttpClient httpClient;

    public HttpImageClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    // 漏洞点：直接使用用户提供的URL发起请求
    public CompletableFuture<String> getThumbnailContent(String thumbnailUrl) {
        return httpClient.sendAsync(
            HttpRequest.newBuilder()
                .uri(URI.create(thumbnailUrl))
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString()
        ).thenApply(HttpResponse::body);
    }
}

// 控制器层
public class TaskController {
    private TaskService taskService;
    private HttpImageClient httpImageClient;

    public TaskController(TaskService taskService, HttpImageClient httpImageClient) {
        this.taskService = taskService;
        this.httpImageClient = httpImageClient;
    }

    // 模拟Spring MVC控制器方法
    public CompletableFuture<String> showTask(String taskId, String thumbnailOverride) {
        return taskService.getTaskDetails(taskId, thumbnailOverride)
            .thenCompose(task -> {
                // 漏洞危害体现：返回内部资源内容
                return httpImageClient.getThumbnailContent(task.getThumbnailUrl());
            });
    }
}

// 模拟仓库接口
public interface TaskRepository {
    CompletableFuture<Task> findById(String taskId);
}

// 模拟配置类
public class Main {
    public static void main(String[] args) {
        TaskRepository repository = id -> CompletableFuture.completedFuture(
            new Task("1", "Sample Task", "https://example.com/default.jpg")
        );
        
        TaskService taskService = new TaskService(repository);
        HttpImageClient client = new HttpImageClient();
        TaskController controller = new TaskController(taskService, client);
        
        // 模拟攻击请求
        controller.showTask("1", "file:///etc/passwd")
            .thenAccept(System.out::println)
            .join();
    }
}