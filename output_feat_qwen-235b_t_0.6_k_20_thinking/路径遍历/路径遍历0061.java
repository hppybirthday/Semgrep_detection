package com.example.mathsim.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

@RestController
@RequestMapping("/api/models")
public class MathModelController {
    
    @Value("${storage.base-directory}")
    private String baseDirectory;

    @DeleteMapping("/files/{filename}")
    public String deleteModelFile(@PathVariable String filename) {
        try {
            StorageService storage = new StorageService(baseDirectory);
            storage.deleteModelFile(filename);
            return "File deleted successfully";
        } catch (Exception e) {
            return "Error deleting file: " + e.getMessage();
        }
    }

    @PostMapping("/upload")
    public String uploadModelFile(@RequestParam("file") String content, 
                                 @RequestParam("name") String filename) {
        try {
            StorageService storage = new StorageService(baseDirectory);
            storage.storeModelFile(filename, content.getBytes());
            return "File uploaded successfully";
        } catch (Exception e) {
            return "Error uploading file: " + e.getMessage();
        }
    }
}

class StorageService {
    private final String baseDir;

    public StorageService(String baseDir) {
        this.baseDir = baseDir;
    }

    public void storeModelFile(String filename, byte[] content) throws IOException {
        // 危险的路径拼接方式
        File targetFile = new File(baseDir + File.separator + filename);
        
        // 未检查路径是否超出限制目录
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(content);
        }
    }

    public void deleteModelFile(String filename) throws IOException {
        // 直接使用用户输入构造文件对象
        File targetFile = new File(baseDir + File.separator + filename);
        
        // 可能删除任意系统文件
        if (targetFile.exists()) {
            Files.delete(targetFile.toPath());
        }
    }
}