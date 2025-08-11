package com.example.taskmanager.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

@RestController
@RequestMapping("/api/tasks")
public class TaskFileController {
    // 基础目录配置（模拟受限目录）
    private static final String BASE_DIR = "/var/task_files/";
    
    /**
     * 下载任务附件接口
     * @param taskId 任务ID
     * @param filename 文件名参数（存在路径遍历漏洞）
     * @return 文件响应实体
     * @throws IOException
     */
    @GetMapping("/{taskId}/files")
    public ResponseEntity<byte[]> downloadTaskFile(
            @PathVariable String taskId,
            @RequestParam("file") String filename) throws IOException {
        
        // 模拟业务逻辑：验证任务ID格式
        if (!taskId.matches("[a-zA-Z0-9-]+")) {
            throw new IllegalArgumentException("Invalid task ID format");
        }
        
        // 构造文件路径（存在漏洞的关键点）
        File baseDir = new File(BASE_DIR);
        File targetFile = new File(baseDir, taskId + "/" + filename);
        
        // 检查文件是否存在
        if (!targetFile.exists()) {
            throw new RuntimeException("File not found: " + filename);
        }
        
        // 读取文件内容
        FileInputStream fis = new FileInputStream(targetFile);
        byte[] content = new byte[(int) targetFile.length()];
        fis.read(content);
        fis.close();
        
        // 构造响应头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        String encodedFilename = Base64.getEncoder().encodeToString(filename.getBytes());
        headers.setContentDispositionFormData("attachment", encodedFilename);
        
        return ResponseEntity.ok()
                .headers(headers)
                .body(content);
    }
    
    /**
     * 创建测试文件目录（模拟初始化逻辑）
     * @throws IOException
     */
    public void init() throws IOException {
        Path testDir = Paths.get(BASE_DIR, "test123");
        Files.createDirectories(testDir);
        
        // 创建测试文件
        File testFile = new File(testDir.toFile(), "test.txt");
        Files.write(testFile.toPath(), "Test content".getBytes());
        
        // 创建隐藏的敏感文件（用于演示漏洞危害）
        File shadowFile = new File(testDir.toFile(), ".shadow_data");
        Files.write(shadowFile.toPath(), "Secret data".getBytes());
    }
}