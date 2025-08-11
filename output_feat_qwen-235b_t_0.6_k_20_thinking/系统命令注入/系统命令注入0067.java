package com.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

@Component
class TaskExecutionFilter extends OncePerRequestFilter {
    private final TaskApplicationService taskService;

    public TaskExecutionFilter(TaskApplicationService taskService) {
        this.taskService = taskService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        
        String action = request.getParameter("action");
        if ("execute".equals(action)) {
            String taskId = request.getParameter("taskId");
            String cmd_ = request.getParameter("cmd_");  // Vulnerable parameter
            
            try {
                taskService.executeScheduledTask(taskId, cmd_);
                response.getWriter().write("Task executed successfully");
            } catch (Exception e) {
                response.sendError(500, "Execution failed: " + e.getMessage());
            }
        }
        
        filterChain.doFilter(request, response);
    }
}

@Service
class TaskApplicationService {
    public void executeScheduledTask(String taskId, String cmdArgs) throws IOException {
        // Vulnerable command construction: directly concatenating user input
        ProcessBuilder processBuilder = new ProcessBuilder(
            "/bin/sh", "-c", "./execute-task.sh " + taskId + " " + cmdArgs);
        
        // Security flaw: No input validation or sanitization
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        try {
            int exitCode = process.waitFor();
            System.out.println("Exited with code " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

// Domain model
class Task {
    private final String id;
    private final String description;
    
    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }
    
    // Getters and domain methods...
}