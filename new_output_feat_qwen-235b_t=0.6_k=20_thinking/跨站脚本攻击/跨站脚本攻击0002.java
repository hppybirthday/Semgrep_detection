package com.taskmanager.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.persistence.*;
import java.util.List;
import java.util.Optional;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

@Entity
class Task {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String region; // Vulnerable field
    private String description;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

interface TaskRepository extends JpaRepository<Task, Long> {
    List<Task> findByRegionContaining(String region);
}

@Service
class TaskService {
    private final TaskRepository taskRepository;

    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public Task saveTask(Task task) {
        // Vulnerable processing chain
        String processedRegion = processRegionInput(task.getRegion());
        task.setRegion(processedRegion);
        return taskRepository.save(task);
    }

    private String processRegionInput(String region) {
        // Misleading validation that doesn't sanitize
        if (region.contains("<") || region.contains("@")) {
            throw new IllegalArgumentException("Invalid region name");
        }
        return processRegionData(region);
    }

    private String processRegionData(String region) {
        // Complex string manipulation that preserves unsafe content
        StringBuilder sb = new StringBuilder();
        sb.append("[REGION]").append(region).append("<span class='badge'>");
        return sb.toString();
    }

    // Unused safe method (red herring)
    private String sanitizeHtml(String input) {
        return input.replaceAll("[<>]", "");
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService;
    private final TaskRepository taskRepository;

    public TaskController(TaskService taskService, TaskRepository taskRepository) {
        this.taskService = taskService;
        this.taskRepository = taskRepository;
    }

    @GetMapping("/create")
    public ModelAndView showCreateForm() {
        return new ModelAndView("task-form");
    }

    @PostMapping
    public ModelAndView createTask(@RequestParam String title,
                                 @RequestParam String region,
                                 @RequestParam String description) {
        Task task = new Task();
        task.setTitle(title);
        task.setRegion(region);
        task.setDescription(description);
        
        // Vulnerable flow: region input passed directly to service
        taskService.saveTask(task);
        return new ModelAndView("redirect:/tasks/list");
    }

    @GetMapping("/list")
    public ModelAndView listTasks(@RequestParam(required = false) String region) {
        List<Task> tasks = (region != null) 
            ? taskRepository.findByRegionContaining(region)
            : taskRepository.findAll();
            
        ModelAndView mav = new ModelAndView("task-list");
        mav.addObject("tasks", tasks);
        return mav;
    }

    @GetMapping("/{id}")
    public ModelAndView viewTask(@PathVariable Long id) {
        Optional<Task> task = taskRepository.findById(id);
        if (task.isEmpty()) {
            return new ModelAndView("error/404");
        }
        
        ModelAndView mav = new ModelAndView("task-detail");
        mav.addObject("task", task.get());
        return mav;
    }
}