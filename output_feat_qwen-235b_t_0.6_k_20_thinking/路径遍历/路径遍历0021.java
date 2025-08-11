package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

@RestController
@RequestMapping("/api/files")
public class FileController {
    private static final Logger logger = Logger.getLogger(FileController.class.getName());
    private static final String BASE_DIR = "/var/www/html/static/";

    @PostMapping("/create")
    public String createFile(@RequestParam String filename, @RequestParam String content) {
        try {
            // 漏洞点：直接拼接用户输入到基础路径
            Path targetPath = Paths.get(BASE_DIR + filename);
            
            // 创建父目录（可能创建任意路径）
            Files.createDirectories(targetPath.getParent());
            
            // 创建新文件并写入内容
            Files.createFile(targetPath);
            try (BufferedWriter writer = Files.newBufferedWriter(targetPath)) {
                writer.write(content);
            }
            
            logger.info("文件创建成功: " + targetPath.toString());
            return "文件创建成功";
            
        } catch (Exception e) {
            logger.severe("文件操作失败: " + e.getMessage());
            return "文件操作失败: " + e.getMessage();
        }
    }
    
    // 模拟服务层调用
    @GetMapping("/demo")
    public String demoUsage() {
        // 示例调用：创建测试文件
        createFile("test.txt", "示例内容");
        return "已创建测试文件";
    }
    
    // 主应用类
    public static class Application {
        public static void main(String[] args) {
            // 模拟启动代码（实际应使用Spring Boot启动）
            System.out.println("Vulnerable app started");
        }
    }
}