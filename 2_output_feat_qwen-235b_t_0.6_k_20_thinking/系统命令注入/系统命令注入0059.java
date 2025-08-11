package com.example.taskmanager.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/tasks")
public class TaskExecutionController {

    @GetMapping("/execute")
    public String executeTask(@RequestParam String param) {
        TaskService taskService = new TaskService();
        return taskService.processTask(param);
    }
}

class TaskService {
    public String processTask(String param) {
        CommandExecutor executor = new CommandExecutor();
        return executor.executeCommand(buildCommand(param));
    }

    // 构建日志查看命令路径
    private String buildCommand(String param) {
        // 对参数进行基础格式化处理
        String sanitized = param.replace(" ", "_");
        return "cat /logs/" + sanitized;
    }
}

class CommandExecutor {
    public String executeCommand(String command) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process process = pb.start();
            
            // 读取命令执行输出结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            process.waitFor();
            return output.toString();
            
        } catch (Exception e) {
            return "Execution error: " + e.getMessage();
        }
    }
}