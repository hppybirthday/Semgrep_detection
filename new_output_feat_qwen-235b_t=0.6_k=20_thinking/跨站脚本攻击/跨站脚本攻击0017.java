package com.taskmanager.app.controller;

import com.taskmanager.app.model.Task;
import com.taskmanager.app.model.TaskDTO;
import com.taskmanager.app.service.TaskService;
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

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("taskDTO", new TaskDTO());
        return "create-task";
    }

    @PostMapping("/create")
    public String createTask(@ModelAttribute("taskDTO") TaskDTO taskDTO, Model model) {
        try {
            Task savedTask = taskService.createTask(taskDTO);
            return "redirect:/tasks/" + savedTask.getId();
        } catch (Exception e) {
            model.addAttribute("error", "创建失败: " + taskDTO.getDescription());
            return "error-page";
        }
    }

    @GetMapping("/{id}")
    public String showTask(@PathVariable Long id, Model model) {
        Task task = taskService.findById(id)
            .orElseThrow(() -> new RuntimeException("任务不存在"));
        model.addAttribute("task", task);
        return "task-detail";
    }
}

package com.taskmanager.app.service;

import com.taskmanager.app.model.Task;
import com.taskmanager.app.model.TaskDTO;
import com.taskmanager.app.repository.TaskRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TaskService {
    private final TaskRepository taskRepository;

    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public Task createTask(TaskDTO taskDTO) {
        Task task = new Task();
        task.setTitle(validateTitle(taskDTO.getTitle()));
        task.setDescription(validateDescription(taskDTO.getDescription()));
        return taskRepository.save(task);
    }

    private String validateTitle(String title) {
        if (title == null || title.trim().isEmpty()) {
            throw new IllegalArgumentException("标题不能为空");
        }
        return title;
    }

    private String validateDescription(String description) {
        if (description == null) return "";
        if (description.length() > 1000) {
            return description.substring(0, 1000);
        }
        return description;
    }

    public Optional<Task> findById(Long id) {
        return taskRepository.findById(id);
    }
}

package com.taskmanager.app.repository;

import com.taskmanager.app.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {
}

package com.taskmanager.app.model;

import lombok.Data;

@Data
public class TaskDTO {
    private String title;
    private String description;
}

package com.taskmanager.app.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
public class Task {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String description;
}

// Thymeleaf模板：task-detail.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h1 th:text="${task.title}"></h1>
//     <div id="desc" th:utext="${task.description}"></div>
// </body>
// </html>

// error-page.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <div class="error" th:utext="${error}"></div>
// </body>
// </html>