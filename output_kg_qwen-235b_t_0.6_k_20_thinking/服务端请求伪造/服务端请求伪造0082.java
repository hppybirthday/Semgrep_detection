package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping
    public Task createTask(@RequestBody TaskDTO dto) {
        return taskService.createTask(dto.getDescription(), dto.getCallbackUrl());
    }

    @GetMapping("/{id}")
    public Task getTask(@PathVariable Long id) {
        return taskService.getTask(id);
    }
}

@Service
class TaskService {
    @Autowired
    private TaskRepository taskRepository;

    @Autowired
    private RestTemplate restTemplate;

    public Task createTask(String description, String callbackUrl) {
        Task task = new Task();
        task.setDescription(description);
        task.setCallbackUrl(callbackUrl);
        return taskRepository.save(task);
    }

    public Task getTask(Long id) {
        Task task = taskRepository.findById(id).orElseThrow();
        if (task.getCallbackUrl() != null && !task.getCallbackUrl().isEmpty()) {
            // 漏洞点：直接使用用户提供的URL发起请求
            String response = restTemplate.getForObject(task.getCallbackUrl(), String.class);
            task.setExternalData(response);
        }
        return taskRepository.save(task);
    }
}

interface TaskRepository extends JpaRepository<Task, Long> {}

@Entity
class Task {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String description;
    private String callbackUrl;
    @Lob
    private String externalData;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
    public String getExternalData() { return externalData; }
    public void setExternalData(String externalData) { this.externalData = externalData; }
}

record TaskDTO(String description, String callbackUrl) {}
