package com.example.vulnerableapp.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

@RestController
@RequestMapping("/api/files")
public class FileDownloadController {
    private static final String BASE_PATH = "/var/www/html/uploads/";
    private static final Logger logger = Logger.getLogger(FileDownloadController.class.getName());

    @GetMapping("/{filename}")
    public String downloadFile(@PathVariable String filename) {
        try {
            // 漏洞点：直接拼接用户输入到文件路径
            Path filePath = Paths.get(BASE_PATH + filename);
            
            // 模拟文件处理逻辑
            if (!filePath.normalize().startsWith(BASE_PATH)) {
                logger.warning("路径越权访问尝试: " + filename);
                return "Access Denied";
            }

            // 模拟文件读取
            if (!Files.exists(filePath)) {
                return "File Not Found";
            }

            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = Files.newBufferedReader(filePath)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\
");
                }
            }
            
            return content.toString();
            
        } catch (Exception e) {
            logger.severe("文件操作错误: " + e.getMessage());
            return "Internal Server Error";
        }
    }

    // 模拟元编程风格的动态处理方法
    private Object processFileOperation(String operation, String... params) {
        try {
            switch (operation) {
                case "read":
                    return Files.readAllBytes(Paths.get(BASE_PATH + params[0]));
                case "exists":
                    return Files.exists(Paths.get(BASE_PATH + params[0]));
                default:
                    throw new IllegalArgumentException("未知操作: " + operation);
            }
        } catch (Exception e) {
            logger.warning("动态操作失败: " + e.getMessage());
            return "操作失败: " + e.getMessage();
        }
    }

    // 漏洞暴露接口
    @GetMapping("/dynamic/{op}")
    public String dynamicFileOp(@PathVariable String op, @RequestParam String file) {
        Object result = processFileOperation(op, file);
        return result.toString();
    }
}