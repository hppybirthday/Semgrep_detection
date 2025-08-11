package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
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
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService = new TaskService();

    @GetMapping("/create")
    @ResponseBody
    String createForm() {
        return "<form method='post' action='/tasks/create'>"
               + "Title: <input name='title'/><br>"
               + "Description: <input name='description'/><br>"
               + "<button type='submit'>Create</button></form>";
    }

    @PostMapping("/create")
    String createTask(@RequestParam String title, @RequestParam String description) {
        taskService.createTask(title, description);
        return "redirect:/tasks/list";
    }

    @GetMapping("/list")
    @ResponseBody
    String listTasks() {
        StringBuilder html = new StringBuilder("<ul>");
        for (Task task : taskService.getAllTasks()) {
            html.append("<li>")
                .append("<a href='/tasks/" + task.getId() + "'>")
                .append(task.getTitle())
                .append("</a></li>");
        }
        html.append("</ul>");
        return html.toString();
    }

    @GetMapping("/{id}")
    @ResponseBody
    String viewTask(@PathVariable Long id) {
        Task task = taskService.getTaskById(id);
        if (task == null) return "Not found";
        return "<div><h1>" + task.getTitle() + "</h1>"
               + "<div>" + task.getDescription() + "</div></div>";
    }
}

class Task {
    private static Long idCounter = 1L;
    private final Long id = idCounter++;
    private final String title;
    private String description;

    Task(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

class TaskService {
    private final List<Task> tasks = new ArrayList<>();

    void createTask(String title, String description) {
        tasks.add(new Task(title, description));
    }

    List<Task> getAllTasks() {
        return tasks;
    }

    Task getTaskById(Long id) {
        return tasks.stream().filter(t -> t.getId().equals(id)).findFirst().orElse(null);
    }
}