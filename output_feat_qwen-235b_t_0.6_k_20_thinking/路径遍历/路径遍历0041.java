package com.example.demo;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/categories")
public class CategoryController {
    // 模拟OSS配置
    private static final String BASE_PATH = "/data/uploads/";
    
    // 模拟OSS分片上传接口
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("bizPath") String bizPath,
                                   @RequestParam("content") String content) {
        try {
            // 路径拼接错误示范（存在路径遍历漏洞）
            Path targetPath = Paths.get(BASE_PATH, bizPath);
            
            // 创建目标目录结构
            Files.createDirectories(targetPath.getParent());
            
            // 模拟分片写入
            try (BufferedWriter writer = Files.newBufferedWriter(targetPath)) {
                writer.write(content);
            }
            
            return "Upload successful to: " + targetPath.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟分类管理操作
    @PostMapping("/manage")
    public String manageCategory(@RequestParam("action") String action,
                                @RequestParam("filePath") String filePath) {
        // 构造日志记录路径（二次漏洞触发）
        Path logPath = Paths.get(BASE_PATH, "logs", filePath);
        
        try {
            // 错误的日志记录操作
            Files.write(logPath, ("Action: " + action + "\
").getBytes(),
                      StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return "Log recorded at: " + logPath.toString();
            
        } catch (Exception e) {
            return "Log error: " + e.getMessage();
        }
    }
    
    // 初始化配置目录
    static {
        try {
            Files.createDirectories(Paths.get(BASE_PATH, "logs"));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create base directory");
        }
    }
}