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

    @PostMapping
    public String addTask(@RequestParam String title, @RequestParam String description) {
        taskService.addTask(new Task(title, description));
        return "redirect:/tasks";
    }

    @GetMapping("/{id}")
    public String viewTask(@PathVariable Long id, Model model) {
        Task task = taskService.getTaskById(id);
        model.addAttribute("task", task);
        return "task-detail";
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

    public void addTask(Task task) {
        tasks.add(task);
    }

    public Task getTaskById(Long id) {
        return tasks.stream().filter(t -> t.getId().equals(id)).findFirst().orElse(null);
    }
}

// Task.java
package com.example.taskmanager.model;

import java.util.Objects;

public class Task {
    private Long id;
    private String title;
    private String description;

    public Task(String title, String description) {
        this.id = System.currentTimeMillis();
        this.title = title;
        this.description = description;
    }

    // Getters and setters
    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

// task-detail.jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head><title>Task Detail</title></head>
<body>
    <h1>${task.title}</h1>
    <div>${task.description}</div>  <!-- Vulnerable line -->
    <a href="/tasks">Back to list</a>
</body>
</html>