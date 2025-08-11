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

// 实体层
class Task {
    private String title;
    private String description;
    
    // Getters and Setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// 仓储接口
interface TaskRepository {
    void save(Task task);
    List<Task> findAll();
}

// 领域服务
@Service
class InMemoryTaskRepository implements TaskRepository {
    private List<Task> tasks = new ArrayList<>();
    @Override
    public void save(Task task) { tasks.add(task); }
    @Override
    public List<Task> findAll() { return tasks; }
}

// 应用服务
@Service
class TaskService {
    private TaskRepository repository;
    public TaskService(TaskRepository repository) { this.repository = repository; }
    public void createTask(Task task) { repository.save(task); }
    public List<Task> getAllTasks() { return repository.findAll(); }
}

// 接口层
@Controller
class TaskController {
    private TaskService taskService;
    public TaskController(TaskService taskService) { this.taskService = taskService; }

    @GetMapping("/tasks")
    public String listTasks(Model model) {
        model.addAttribute("tasks", taskService.getAllTasks());
        return "tasks"; // 返回视图名称
    }

    @PostMapping("/tasks")
    public String addTask(@RequestParam String title, @RequestParam String description) {
        Task task = new Task();
        task.setTitle(title);
        task.setDescription(description); // 直接存储原始输入
        taskService.createTask(task);
        return "redirect:/tasks";
    }
}

// View (tasks.jsp) 中的漏洞点：
// <div class="task">
//   <h3>${task.title}</h3>
//   <p>${task.description}</p> <!-- 这里未转义输出 -->
// </div>