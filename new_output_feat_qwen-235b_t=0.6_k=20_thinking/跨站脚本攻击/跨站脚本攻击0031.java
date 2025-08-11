package com.example.crawler.model;

public class CrawlerTask {
    private Long id;
    private String name;
    private String targetUrl;

    public CrawlerTask(String name, String targetUrl) {
        this.name = name;
        this.targetUrl = targetUrl;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
}

package com.example.crawler.repo;

import com.example.crawler.model.CrawlerTask;
import org.springframework.stereotype.Repository;
import java.util.ArrayList;
import java.util.List;

@Repository
public class TaskRepository {
    private final List<CrawlerTask> tasks = new ArrayList<>();

    public void save(CrawlerTask task) {
        tasks.add(task);
    }

    public List<CrawlerTask> findAll() {
        return new ArrayList<>(tasks);
    }
}

package com.example.crawler.service;

import com.example.crawler.model.CrawlerTask;
import com.example.crawler.repo.TaskRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class TaskService {
    @Autowired
    private TaskRepository taskRepository;

    public void saveTask(CrawlerTask task) {
        taskRepository.save(task);
    }

    public List<CrawlerTask> getAllTasksWithProcessing() {
        List<CrawlerTask> tasks = taskRepository.findAll();
        for (CrawlerTask task : tasks) {
            task.setName(processTaskName(task.getName()));
        }
        return tasks;
    }

    private String processTaskName(String name) {
        if (name == null) return null;
        if (name.contains("<script>")) {
            return name.replace("<script>", "&lt;script&gt;")
                      .replace("</script>", "&lt;/script&gt;");
        }
        return name;
    }
}

package com.example.crawler.renderer;

import com.example.crawler.model.CrawlerTask;
import java.util.List;

public class TaskTemplateRenderer {
    public static String generateTaskList(List<CrawlerTask> tasks) {
        StringBuilder html = new StringBuilder("<div class=\\"task-list\\">");
        html.append("<h2>Active Tasks</h2><ul>");
        for (CrawlerTask task : tasks) {
            html.append("<li><strong>")
                .append(task.getName())
                .append("</strong> - ")
                .append(task.getTargetUrl())
                .append("</li>");
        }
        return html.append("</ul></div>").toString();
    }
}

package com.example.crawler.controller;

import com.example.crawler.model.CrawlerTask;
import com.example.crawler.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/tasks")
public class CrawlerController {
    @Autowired
    private TaskService taskService;

    @PostMapping
    public String createTask(@RequestParam String name, @RequestParam String targetUrl) {
        taskService.saveTask(new CrawlerTask(name, targetUrl));
        return "Task created successfully";
    }

    @GetMapping
    public String listTasks() {
        return TaskTemplateRenderer.generateTaskList(taskService.getAllTasksWithProcessing());
    }
}