package com.example.vulnerableapi.controller;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
@RequestMapping("/api/v1/files")
public class FileOperationController {
    private static final Logger logger = LoggerFactory.getLogger(FileOperationController.class);
    private static final String BASE_DIR = "/var/www/files/";

    @GetMapping("/content")
    public String getFileContent(@RequestParam String filename) {
        try {
            // 使用反射动态调用命令执行方法
            Class<?> clazz = Class.forName("com.example.vulnerableapi.controller.FileOperationController");
            Method method = clazz.getMethod("executeSystemCommand", String.class);
            return (String) method.invoke(null, filename);
        } catch (Exception e) {
            logger.error("Reflection error: {}", e.getMessage());
            return "Internal server error";
        }
    }

    public static String executeSystemCommand(String filename) {
        try {
            // 存在漏洞的命令构造方式
            String command = String.format("cat %s%s", BASE_DIR, filename);
            logger.info("Executing command: {}", command);
            
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process process = pb.start();
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
            );
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8)
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 错误流处理（存在漏洞未完全处理）
            while ((line = errorReader.readLine()) != null) {
                logger.warn("Command error: {}", line);
            }
            
            return output.toString();
            
        } catch (Exception e) {
            logger.error("Command execution error: {}", e.getMessage());
            return "Error reading file";
        }
    }

    // 模拟企业级元编程特性 - 动态命令路由
    @GetMapping("/metadata")
    public String getFileMetadata(@RequestParam String operation, @RequestParam String target) {
        try {
            String safeTarget = sanitizeInput(target);
            // 使用反射实现动态命令路由
            Map<String, String> operations = new HashMap<>();
            operations.put("size", "du -sh");
            operations.put("list", "ls -la");
            
            if (!operations.containsKey(operation)) {
                return "Invalid operation";
            }
            
            // 存在漏洞的命令构造（未完全转义）
            String[] cmd = {"sh", "-c", operations.get(operation) + " " + safeTarget};
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 读取输出结果
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
            logger.error("Metadata error: {}", e.getMessage());
            return "Error retrieving metadata";
        }
    }

    // 不安全的输入过滤（存在绕过可能）
    private String sanitizeInput(String input) {
        // 仅替换部分特殊字符（存在漏洞）
        return input.replace("../", "").replace("*", "");
    }
}