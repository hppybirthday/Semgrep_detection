package com.example.bigdata.security;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;

/**
 * Copyright 2023 BigData Security Inc.
 * 
 * 该代码模拟大数据处理场景中的路径遍历漏洞
 * 漏洞点：未验证用户输入的文件路径，直接拼接构造目标路径
 */
@RestController
@RequestMapping("/data")
public class DataProcessingController {
    
    // 模拟大数据处理目录
    private static final String BASE_DIR = "/var/bigdata/warehouse/";
    
    /**
     * 接收客户端上传的数据文件
     * @param filePath 用户指定的文件路径
     * @param content 用户上传的数据内容（Base64编码）
     * @return 操作结果
     */
    @PostMapping("/upload")
    public String uploadData(@RequestParam String filePath, @RequestParam String content) {
        try {
            // 构造目标文件路径（存在漏洞的关键点）
            Path targetPath = Paths.get(BASE_DIR + filePath);
            
            // 创建父目录（可能创建任意目录）
            Files.createDirectories(targetPath.getParent());
            
            // 解码并写入文件
            byte[] data = Base64.getDecoder().decode(content);
            
            // 使用原子写入操作
            Path tempFile = Files.createTempFile("upload_", ".tmp");
            Files.write(tempFile, data);
            
            // 移动到目标位置
            Files.move(tempFile, targetPath, StandardCopyOption.REPLACE_EXISTING);
            
            return "File uploaded to: " + targetPath.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * 下载数据文件接口（同样存在漏洞）
     * @param filePath 请求下载的文件路径
     * @return 文件内容
     */
    @GetMapping("/download")
    public String downloadData(@RequestParam String filePath) {
        try {
            Path targetPath = Paths.get(BASE_DIR + filePath);
            
            // 读取文件内容
            byte[] data = Files.readAllBytes(targetPath);
            return Base64.getEncoder().encodeToString(data);
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public static void main(String[] args) throws IOException {
        // 初始化目录
        Files.createDirectories(Paths.get(BASE_DIR));
        
        // 启动Spring Boot应用（此处省略具体实现）
        System.out.println("DataProcessingController started");
    }
}