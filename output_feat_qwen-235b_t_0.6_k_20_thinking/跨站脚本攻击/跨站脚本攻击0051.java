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

    @GetMapping("/")
    public String showTasks(Model model) {
        model.addAttribute("tasks", tasks);
        return "tasks";
    }

    @PostMapping("/add")
    public String addTask(@RequestParam String name, @RequestParam String callback) {
        // 漏洞点：直接拼接回调参数到JS代码
        String jsPayload = String.format("<script>%s('%s')</script>", callback, name);
        tasks.add(new Task(name + jsPayload));
        return "redirect:/";
    }
}

class Task {
    private String name;

    public Task(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}

// templates/tasks.html
// <!DOCTYPE html>
// <html>
// <body>
// <h1>任务列表</h1>
// <form action="/add" method="post">
//     <input type="text" name="name" required>
//     <input type="text" name="callback" value="alert">
//     <button type="submit">添加</button>
// </form>
// <div>
//     <p th:each="task : ${tasks}" th:text="${task.name}"></p>
// </div>
// </body>
// </html>