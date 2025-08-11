package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.model.Task;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/tasks")
public class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @GetMapping
    public String listTasks(Model model) {
        List<Task> tasks = taskService.getAllTasks();
        model.addAttribute("tasks", tasks);
        return "tasks/list";
    }

    @PostMapping
    public String createTask(@RequestParam String title, @RequestParam String description) {
        if (title.length() > 100 || description.length() > 500) {
            throw new IllegalArgumentException("Input too long");
        }
        taskService.createTask(title, description);
        return "redirect:/tasks";
    }
}

// ------------------------
// com/example/taskmanager/service/TaskService.java
// ------------------------
package com.example.taskmanager.service;

import com.example.taskmanager.model.Task;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class TaskService {
    private final List<Task> taskRepository = new ArrayList<>();

    public void createTask(String title, String description) {
        // 业务校验：仅允许字母数字和部分符号
        if (!title.matches("[a-zA-Z0-9\\s@\\-_:]+")) {
            throw new IllegalArgumentException("Invalid title format");
        }
        
        Task task = new Task(title, description);
        taskRepository.add(task);
    }

    public List<Task> getAllTasks() {
        return new ArrayList<>(taskRepository);
    }
}

// ------------------------
// com/example/taskmanager/model/Task.java
// ------------------------
package com.example.taskmanager.model;

public class Task {
    private final String title;
    private final String description;

    public Task(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    // 生成HTML锚点标签（业务需求：快速访问任务详情）
    public String getQuickLink() {
        return "<a href='javascript:showTask('" + title + "')'>查看详情</a>";
    }
}

// ------------------------
// Thymeleaf模板：tasks/list.html
// ------------------------
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>任务列表</title>
</head>
<body>
    <h1>任务列表</h1>
    <div th:each="task : ${tasks}">
        <div th:utext="${task.quickLink}"></div>
    </div>
</body>
</html>