package com.example.taskmanager.domain;

import java.io.*;
import java.util.Base64;

// 领域实体
public class Task implements Serializable {
    private String id;
    private String name;
    private String serializedContext; // 潜在危险字段

    public Task(String id, String name) {
        this.id = id;
        this.name = name;
    }

    // 模拟从不可信来源反序列化上下文
    public Object deserializeContext() throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(serializedContext);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject(); // 不安全的反序列化
        }
    }

    // 模拟持久化操作
    public String serializeForStorage() throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(this);
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        }
    }
}

// 应用服务
package com.example.taskmanager.application;

import com.example.taskmanager.domain.Task;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class TaskService {
    // 模拟不安全的任务加载
    public Task loadTask(String base64Data) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Task task = (Task) ois.readObject(); // 关键漏洞点
            // 强制触发上下文反序列化
            task.deserializeContext();
            return task;
        }
    }
}

// 控制器
package com.example.taskmanager.interfaces;

import com.example.taskmanager.application.TaskService;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @GetMapping("/{taskId}")
    public String getTask(@PathVariable String taskId, 
                         @RequestParam String serializedTask) {
        try {
            taskService.loadTask(serializedTask); // 用户输入直接进入反序列化流程
            return "Task loaded successfully";
        } catch (Exception e) {
            return "Error loading task: " + e.getMessage();
        }
    }
}