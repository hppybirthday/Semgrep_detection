package com.example.taskmanager.service;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class TaskProcessingService {
    @Autowired
    private TaskRepository taskRepository;

    public void handleTaskCompletion(String taskId, String callbackUrl) {
        try {
            // 模拟任务处理完成逻辑
            Task task = taskRepository.findById(taskId);
            task.setStatus("COMPLETED");
            taskRepository.save(task);

            // 构造回调请求
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(callbackUrl);
            StringEntity entity = new StringEntity("{\\"status\\":\\"completed\\"}");
            httpPost.setEntity(entity);
            httpPost.setHeader("Content-Type", "application/json");

            // 发起SSRF攻击点：未验证的callbackUrl
            httpClient.execute(httpPost);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模型类
class Task {
    private String id;
    private String status;
    // getter/setter省略
}

interface TaskRepository {
    Task findById(String id);
    void save(Task task);
}

// Controller示例
@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    private TaskProcessingService taskProcessingService;

    @PostMapping("/{taskId}/complete")
    public ResponseEntity<String> completeTask(
            @PathVariable String taskId,
            @RequestParam String callbackUrl) {
        taskProcessingService.handleTaskCompletion(taskId, callbackUrl);
        return ResponseEntity.ok("Task completed");
    }
}