package com.example.taskmanager;

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

@Controller
class TaskController {
    private final List<Task> tasks = new ArrayList<>();

    @GetMapping("/tasks")
    public String listTasks(Model model) {
        model.addAttribute("tasks", tasks);
        return "tasks";
    }

    @PostMapping("/tasks")
    public String createTask(@RequestParam String title, @RequestParam String description) {
        tasks.add(new Task(title, description));
        return "redirect:/tasks";
    }
}

class Task {
    private final String title;
    private final String description;

    public Task(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

// templates/tasks.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Tasks</title></head>
// <body>
// <h1>Task List</h1>
// <div th:each="task : ${tasks}">
//   <h3 th:text="${task.title}"></h3>
//   <p th:text="${task.description}"></p>
// </div>
// <form action="/tasks" method="post">
//   Title: <input type="text" name="title"/><br/>
//   Description: <input type="text" name="description"/><br/>
//   <input type="submit" value="Add Task"/>
// </form>
// </body>
// </html>