package com.example.taskmanager.domain;

import org.springframework.stereotype.Service;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 任务执行服务 - 存在系统命令注入漏洞的领域服务
 */
@Service
public class TaskExecutionService {
    
    /**
     * 执行系统命令（存在漏洞版本）
     * @param taskId 任务ID（用于演示）
     * @param userInput 用户输入的参数（未验证）
     * @return 命令执行结果
     * @throws IOException
     */
    public String executeVulnerableCommand(String taskId, String userInput) throws IOException {
        List<String> command = new ArrayList<>();
        
        // 模拟任务执行场景：执行系统命令处理文件
        // 错误示例：直接拼接用户输入到命令参数中
        command.add("/bin/bash");
        command.add("-c");
        command.add("echo \\"Processing task: " + taskId + "\\" && ls -la " + userInput);
        
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
    
    /**
     * 修复后的命令执行方法（示例）
     * @param taskId 任务ID
     * @param safeInput 安全过滤后的输入
     * @return 命令执行结果
     * @throws IOException
     */
    public String executeSafeCommand(String taskId, String safeInput) throws IOException {
        // 正确做法：使用参数化命令，避免字符串拼接
        ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", "echo \\"Processing task: " + taskId + "\\" && ls -la", safeInput);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

// Controller层模拟（简化版）
package com.example.taskmanager.controller;

import com.example.taskmanager.domain.TaskExecutionService;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    private final TaskExecutionService taskExecutionService;

    public TaskController(TaskExecutionService taskExecutionService) {
        this.taskExecutionService = taskExecutionService;
    }

    @GetMapping("/{taskId}/execute")
    public String executeTask(@PathVariable String taskId, 
                            @RequestParam String userInput) throws IOException {
        // 调用存在漏洞的命令执行方法
        return taskExecutionService.executeVulnerableCommand(taskId, userInput);
    }
}

// 领域模型示例
package com.example.taskmanager.domain.model;

import java.time.LocalDateTime;

public class Task {
    private String id;
    private String description;
    private LocalDateTime dueDate;
    private boolean completed;
    
    // 领域逻辑示例
    public boolean isOverdue() {
        return !completed && LocalDateTime.now().isAfter(dueDate);
    }
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public LocalDateTime getDueDate() { return dueDate; }
    public void setDueDate(LocalDateTime dueDate) { this.dueDate = dueDate; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}