package com.taskmanager.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

// 领域实体
class Task {
    private String title;
    private String description;
    private String taskUrl; // 存在漏洞的字段

    public Task(String title, String description, String taskUrl) {
        this.title = title;
        this.description = description;
        this.taskUrl = taskUrl;
    }

    // Getters
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public String getTaskUrl() { return taskUrl; }
}

// 仓储接口
interface TaskRepository {
    void save(Task task);
    List<Task> findAll();
}

// 内存实现
@Component
class InMemoryTaskRepository implements TaskRepository {
    private List<Task> tasks = new ArrayList<>();

    @Override
    public void save(Task task) {
        tasks.add(task);
    }

    @Override
    public List<Task> findAll() {
        return tasks;
    }
}

// 服务层
@Service
class TaskService {
    private TaskRepository repository;

    public TaskService(TaskRepository repository) {
        this.repository = repository;
    }

    public void createTask(String title, String description, String taskUrl) {
        repository.save(new Task(title, description, taskUrl));
    }

    public List<Task> getAllTasks() {
        return repository.findAll();
    }
}

// Web控制器
@Controller
class TaskController {
    private TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @GetMapping("/")
    public String showTasks(Model model) {
        model.addAttribute("tasks", taskService.getAllTasks());
        return "tasks";
    }

    @PostMapping("/add")
    public String addTask(@RequestParam String title, 
                         @RequestParam String description,
                         @RequestParam String taskUrl) {
        taskService.createTask(title, description, taskUrl);
        return "redirect:/";
    }
}

// Thymeleaf模板（src/main/resources/templates/tasks.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>任务列表</title>
</head>
<body>
    <h1>任务管理</h1>
    <form action="/add" method="post">
        标题：<input type="text" name="title"><br>
        描述：<input type="text" name="description"><br>
        链接：<input type="text" name="taskUrl"><br>
        <input type="submit" value="添加任务">
    </form>

    <ul>
    <li th:each="task : ${tasks}">
        <strong th:text="${task.title}"></strong><br>
        <span th:text="${task.description}"></span><br>
        <!-- 存在漏洞的渲染方式 -->
        <a th:href="${task.taskUrl}" target="_blank">访问任务链接</a>
    </li>
    </ul>
</body>
</html>
*/