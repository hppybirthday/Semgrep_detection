package com.example.vulnerableapp.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

@RestController
@RequestMapping("/api/v1")
@Slf4j
public class VulnerableCommandController {
    
    @GetMapping("/execute")
    public String executeCommand(@RequestParam String host) {
        try {
            // 模拟业务场景：执行主机连通性检测
            String command = "ping -c 4 " + host;
            
            log.info("Executing command: {}", command);
            
            ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            
            // 使用原子引用存储结果
            AtomicReference<String> result = new AtomicReference<>("");
            
            // 处理输入流
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                
                String line;
                while ((line = reader.readLine()) != null) {
                    result.updateAndGet(v -> v + line + "\
");
                    log.debug("Command output line: {}", line);
                }
            }
            
            int exitCode = process.waitFor();
            log.info("Command exited with code: {}", exitCode);
            
            return String.format("Command result (exit code %d):\
%s", exitCode, result.get());
            
        } catch (Exception e) {
            log.error("Command execution failed", e);
            return "Error executing command: " + e.getMessage();
        }
    }

    // 模拟业务场景：批量处理命令
    @PostMapping("/batch")
    public String batchCommands(@RequestBody List<String> hosts) {
        StringBuilder results = new StringBuilder();
        
        for (String host : hosts) {
            results.append(executeCommand(host)).append("\
\
");
        }
        
        return results.toString();
    }
    
    // 模拟日志清理命令（隐藏漏洞）
    @GetMapping("/cleanup")
    public String cleanupLogs(@RequestParam String filename) {
        try {
            // 错误地使用字符串拼接构建命令
            Process process = Runtime.getRuntime().exec(
                "sh -c \\"rm -f /var/log/app/" + filename + "\\""
            );
            
            return "Log cleanup executed with exit code: " + process.waitFor();
            
        } catch (Exception e) {
            return "Cleanup failed: " + e.getMessage();
        }
    }
}