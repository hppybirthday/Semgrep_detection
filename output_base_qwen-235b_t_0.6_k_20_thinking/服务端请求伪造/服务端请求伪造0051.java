package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import java.io.IOException;
import java.util.logging.Logger;

@SpringBootApplication
public class TaskManagerApplication {
    private static final Logger logger = Logger.getLogger(TaskManagerApplication.class.getName());

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/tasks")
class TaskController {
    private final RestTemplate restTemplate;

    public TaskController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/fetch")
    public String fetchExternalTaskDetails(@RequestParam String taskUrl) {
        try {
            // Vulnerable: Directly using user input in server-side request without validation
            ResponseEntity<String> response = restTemplate.getForEntity(taskUrl, String.class);
            return "External task details: " + response.getBody();
        } catch (Exception e) {
            return "Error fetching external task: " + e.getMessage();
        }
    }

    // Simulated endpoint for internal task management
    @GetMapping("/internal/admin")
    public String internalAdminEndpoint() {
        return "Sensitive internal admin data exposed through SSRF";
    }
}

// Vulnerability Example:
// An attacker could use this vulnerability to access internal resources:
// Example request: /api/tasks/fetch?taskUrl=http://localhost:8080/api/tasks/internal/admin