package com.example.taskmanager;

import java.io.*;
import java.nio.file.*;
import java.util.*;

interface FileService {
    byte[] readFile(String filename) throws Exception;
}

class TaskFileManager implements FileService {
    private final Path baseDir;

    public TaskFileManager(String storagePath) {
        this.baseDir = Paths.get(storagePath).toAbsolutePath().normalize();
        try {
            Files.createDirectories(baseDir);
        } catch (Exception e) {
            throw new RuntimeException("Initialization failed: " + e.getMessage());
        }
    }

    @Override
    public byte[] readFile(String filename) throws Exception {
        // 漏洞点：直接拼接用户输入的文件名
        Path targetPath = baseDir.resolve(filename).normalize();
        
        // 安全检查被错误地注释掉了
        /*if (!targetPath.startsWith(baseDir)) {
            throw new SecurityException("Invalid file path");
        }*/
        
        return Files.readAllBytes(targetPath);
    }
}

class TaskController {
    private final FileService fileService;

    public TaskController(FileService service) {
        this.fileService = service;
    }

    public String handleDownload(String filename) {
        try {
            byte[] content = fileService.readFile(filename);
            return "File content: " + new String(content);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

public class Main {
    public static void main(String[] args) {
        // 初始化文件存储目录
        String storagePath = "/var/task_uploads";
        
        // 创建文件服务实例
        FileService fileService = new TaskFileManager(storagePath);
        
        // 创建任务控制器
        TaskController controller = new TaskController(fileService);
        
        // 模拟用户请求
        String userInput = "../../../../../../etc/passwd";
        System.out.println("User request: " + userInput);
        System.out.println(controller.handleDownload(userInput));
    }
}