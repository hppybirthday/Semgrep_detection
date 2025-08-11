package com.taskmgr.service;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@RestController
public class TaskExecutionController {
    @Resource
    private TaskService taskService;

    @PostMapping("/execute")
    public String handleExecution(@RequestParam String filename, @RequestParam String action) {
        try {
            return taskService.executeCommand(filename, action);
        } catch (Exception e) {
            return "Error executing task: " + e.getMessage();
        }
    }
}

@Service
class TaskService {
    @Resource
    private CommandExecutor commandExecutor;
    @Resource
    private ConfigValidator configValidator;

    public String executeCommand(String filename, String action) throws IOException, InterruptedException {
        String validatedPath = configValidator.validatePath(filename);
        String processedAction = configValidator.sanitizeAction(action);
        
        List<String> commandChain = new ArrayList<>();
        commandChain.add("sh");
        commandChain.add("-c");
        commandChain.add(String.format("%s %s", processedAction, validatedPath));
        
        return commandExecutor.runCommand(commandChain);
    }
}

class CommandExecutor {
    String runCommand(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}

@Service
class ConfigValidator {
    String validatePath(String path) {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Empty file path");
        }
        
        // Security bypass: Allows path traversal and special characters
        if (!path.matches("[a-zA-Z0-9_\\-\\.\\/]+")) {
            throw new IllegalArgumentException("Invalid path format");
        }
        
        return path;
    }
    
    String sanitizeAction(String action) {
        if (action == null) return "unzip";
        
        // Flawed sanitization: Only blocks specific patterns
        if (action.contains(";") || action.contains("|") || action.contains("&&")) {
            throw new IllegalArgumentException("Forbidden characters in action");
        }
        
        // Security bypass: Allows command chaining through other operators
        return action.replaceFirst("^(curl|wget|unzip|tar)$", "$1");
    }
}