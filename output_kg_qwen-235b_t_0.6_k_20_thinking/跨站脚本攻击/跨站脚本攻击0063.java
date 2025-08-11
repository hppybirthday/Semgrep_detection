package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

// 领域实体
class Task {
    private String id;
    private String title;
    private String description;
    
    public Task(String id, String title, String description) {
        this.id = id;
        this.title = title;
        this.description = description;
    }
    
    // Getters
    public String getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

// 仓储接口
interface TaskRepository {
    void save(Task task);
    List<Task> findAll();
}

// 基础设施实现
class InMemoryTaskRepository implements TaskRepository {
    private final List<Task> tasks = new CopyOnWriteArrayList<>();
    
    @Override
    public void save(Task task) {
        tasks.add(task);
    }
    
    @Override
    public List<Task> findAll() {
        return new ArrayList<>(tasks);
    }
}

// 应用服务
class TaskService {
    private final TaskRepository repository;
    
    public TaskService(TaskRepository repository) {
        this.repository = repository;
    }
    
    public void createTask(String id, String title, String description) {
        repository.save(new Task(id, title, description));
    }
    
    public List<Task> getAllTasks() {
        return repository.findAll();
    }
}

// 接口层
@RestController
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService;
    
    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }
    
    @PostMapping
    public void addTask(@RequestBody Map<String, String> payload) {
        String id = UUID.randomUUID().toString();
        taskService.createTask(id, payload.get("title"), payload.get("description"));
    }
    
    @GetMapping(produces = "text/html")
    public String listTasks() {
        return new TaskHtmlGenerator(taskService.getAllTasks()).generate();
    }
}

// HTML生成器（存在漏洞）
class TaskHtmlGenerator {
    private final List<Task> tasks;
    
    public TaskHtmlGenerator(List<Task> tasks) {
        this.tasks = tasks;
    }
    
    public String generate() {
        StringBuilder html = new StringBuilder();
        html.append("<html><body><h1>任务列表</h1><ul>");
        
        for (Task task : tasks) {
            // 漏洞点：直接拼接用户输入内容
            html.append(String.format(
                "<li><h2>%s</h2><p>%s</p></li>",
                task.getTitle(), task.getDescription()
            ));
        }
        
        html.append("</ul></body></html>");
        return html.toString();
    }
}