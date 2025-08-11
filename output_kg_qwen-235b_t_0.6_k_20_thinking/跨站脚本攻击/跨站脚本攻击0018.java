package com.example.taskmanager.controller;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping
    public String listTasks(Model model) {
        List<Task> tasks = taskService.getAllTasks();
        model.addAttribute("tasks", tasks);
        return "task-list";
    }

    @GetMapping("/new")
    public String showTaskForm(Model model) {
        model.addAttribute("task", new Task());
        return "task-form";
    }

    @PostMapping
    public String createTask(@ModelAttribute("task") Task task) {
        taskService.saveTask(task);
        return "redirect:/tasks";
    }
}

// TaskService.java
package com.example.taskmanager.service;

import com.example.taskmanager.model.Task;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class TaskService {
    private final List<Task> tasks = new ArrayList<>();

    public List<Task> getAllTasks() {
        return tasks;
    }

    public void saveTask(Task task) {
        tasks.add(task);
    }
}

// Task.java
package com.example.taskmanager.model;

public class Task {
    private Long id;
    private String title;
    private String description;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// task-list.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Task List</title>
</head>
<body>
    <h1>Tasks</h1>
    <div th:each="task : ${tasks}">
        <h3 th:text="${task.title}"></h3>
        <p th:text="${task.description}"></p>
    </div>
    <a href="/tasks/new">Create New Task</a>
</body>
</html>

// task-form.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Create Task</title>
</head>
<body>
    <h1>Create New Task</h1>
    <form action="/tasks" method="post">
        <label>Title:</label>
        <input type="text" name="title" required><br>
        <label>Description:</label>
        <textarea name="description"></textarea><br>
        <button type="submit">Create</button>
    </form>
</body>
</html>