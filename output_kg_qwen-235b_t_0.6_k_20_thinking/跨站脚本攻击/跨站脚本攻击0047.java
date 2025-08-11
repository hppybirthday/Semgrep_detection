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
    public String addTask(@RequestParam String title, @RequestParam String description) {
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

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }
}

// templates/tasks.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Task Manager</title></head>
// <body>
// <h1>Tasks</h1>
// <form method="post" action="/tasks">
//     <input type="text" name="title" placeholder="Title">
//     <input type="text" name="description" placeholder="Description">
//     <button type="submit">Add Task</button>
// </form>
// <ul>
// <li th:each="task : ${tasks}">
//     <h3 th:text="${task.title}"></h3>
//     <div th:utext="${task.description}"></div>  // Vulnerable line
// </li>
// </ul>
// </body>
// </html>