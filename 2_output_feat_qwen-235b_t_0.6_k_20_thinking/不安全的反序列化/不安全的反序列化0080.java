package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.util.JsonUtil;
import com.example.taskmanager.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping("/create")
    public String createTask(@RequestBody Map<String, Object> payload) {
        String taskData = (String) payload.get("task");
        Task task = taskService.processTask(taskData);
        return taskService.saveTask(task) ? "SUCCESS" : "FAILURE";
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.util.JsonUtil;
import org.springframework.stereotype.Service;

@Service
public class TaskService {
    public Task processTask(String taskData) {
        if (taskData == null || !JsonUtil.isValidTaskFormat(taskData)) {
            throw new IllegalArgumentException("Invalid task format");
        }
        return JsonUtil.parseTask(taskData);
    }

    public boolean saveTask(Task task) {
        // 模拟业务逻辑
        return task != null && task.validate();
    }
}

package com.example.taskmanager.util;

import com.alibaba.fastjson.JSON;
import com.example.taskmanager.model.Task;

public class JsonUtil {
    public static boolean isValidTaskFormat(String json) {
        // 简单格式校验（易被绕过）
        return json.contains("\\"title\\"") && json.contains("\\"priority\\"");
    }

    public static Task parseTask(String json) {
        // 存在不安全的反序列化漏洞：未限制类型且启用自动类型解析
        return JSON.parseObject(json, Task.class);
    }
}

package com.example.taskmanager.model;

import java.util.Date;

public class Task {
    private String title;
    private int priority;
    private Date dueDate;
    private boolean completed;

    public boolean validate() {
        return title != null && !title.isEmpty() && priority >= 0 && priority <= 5;
    }

    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public int getPriority() { return priority; }
    public void setPriority(int priority) { this.priority = priority; }
    public Date getDueDate() { return dueDate; }
    public void setDueDate(Date dueDate) { this.dueDate = dueDate; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}