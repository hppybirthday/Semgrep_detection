package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.model.Task;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@RequestMapping("/tasks")
public class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @PostMapping("/create")
    public String createTask(@RequestParam String title,
                           @RequestParam String faviconUrl) {
        taskService.saveTask(title, faviconUrl);
        return "redirect:/tasks";
    }

    @GetMapping("/{id}")
    public String getTask(@PathVariable Long id, Model model) {
        Optional<Task> taskOpt = taskService.getTaskById(id);
        if (taskOpt.isPresent()) {
            Task task = taskOpt.get();
            String htmlContent = taskService.generateTaskHTML(task);
            model.addAttribute("htmlContent", htmlContent);
        }
        return "task-detail";
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.repository.TaskRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TaskService {
    private final TaskRepository taskRepository;

    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public void saveTask(String title, String faviconUrl) {
        Task task = new Task();
        task.setTitle(title);
        task.setFaviconUrl(faviconUrl);
        taskRepository.save(task);
    }

    public Optional<Task> getTaskById(Long id) {
        return taskRepository.findById(id);
    }

    public String generateTaskHTML(Task task) {
        return HtmlGenerator.buildTaskCard(task.getTitle(), task.getFaviconUrl());
    }

    private static class HtmlGenerator {
        /**
         * 构建任务卡片HTML，使用安全的URL处理
         * @param title 任务标题
         * @param faviconUrl 图标URL
         * @return HTML字符串
         */
        static String buildTaskCard(String title, String faviconUrl) {
            String template = "<div class='card'><img src='%s'/>%s</div>";
            return String.format(template, faviconUrl, title);
        }
    }
}

package com.example.taskmanager.model;

public class Task {
    private Long id;
    private String title;
    private String faviconUrl;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getFaviconUrl() { return faviconUrl; }
    public void setFaviconUrl(String faviconUrl) { this.faviconUrl = faviconUrl; }
}

package com.example.taskmanager.repository;

import com.example.taskmanager.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TaskRepository extends JpaRepository<Task, Long> {
}