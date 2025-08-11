package com.example.xssdemo.task;

import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    private final TaskService taskService = new TaskService();

    @GetMapping
    public String listTasks(Model model) {
        model.addAttribute("tasks", taskService.getAllTasks());
        return "tasks";
    }

    @PostMapping
    public String createTask(@RequestParam String title, @RequestParam String description) {
        taskService.createTask(title, description);
        return "redirect:/tasks";
    }
}

@Service
class TaskService {
    private final List<Task> tasks = new ArrayList<>();

    public void createTask(String title, String description) {
        tasks.add(new Task(title, description));
    }

    public List<Task> getAllTasks() {
        return tasks;
    }
}

record Task(String title, String description) {}

// src/main/resources/templates/tasks.jsp
// <%@ page contentType="text/html;charset=UTF-8" %>
// <html>
// <body>
//     <h1>Tasks</h1>
//     <ul>
//         ${tasks.stream().map(task -> "<li><h3>" + task.title() + "</h3><p>" + task.description() + "</p></li>").reduce((a,b) -> a + b).orElse("")} 
//     </ul>
//     <form method="post">
//         <input type="text" name="title">
//         <input type="text" name="description">
//         <button type="submit">Add</button>
//     </form>
// </body>
// </html>