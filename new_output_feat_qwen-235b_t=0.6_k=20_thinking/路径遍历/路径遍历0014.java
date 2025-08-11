package com.cloudnative.fileops.controller;

import com.cloudnative.fileops.service.FileMergeService;
import com.cloudnative.fileops.util.FileValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1/files")
public class FileMergeController {
    
    @Autowired
    private FileMergeService fileMergeService;
    
    @Autowired
    private FileValidator fileValidator;
    
    private static final String BASE_UPLOAD_DIR = "/var/www/uploads";
    
    @PostMapping(path = "/merge", consumes = "multipart/form-data")
    public ResponseEntity<String> mergeFileChunks(
        @RequestParam("outputDir") String outputDir,
        @RequestParam("fileName") String fileName,
        @RequestParam("chunkCount") int chunkCount,
        @RequestParam("fileChunks") List<MultipartFile> fileChunks) {
        
        try {
            // 验证输出目录安全性
            if (!fileValidator.isValidDirectory(outputDir)) {
                return ResponseEntity.badRequest().body("Invalid output directory");
            }
            
            Path finalFilePath = Paths.get(BASE_UPLOAD_DIR, outputDir, fileName);
            
            // 创建临时存储目录
            Files.createDirectories(finalFilePath.getParent());
            
            // 合并文件块
            List<byte[]> chunksData = new ArrayList<>();
            for (MultipartFile chunk : fileChunks) {
                chunksData.add(chunk.getBytes());
            }
            
            // 执行文件合并操作
            fileMergeService.mergeChunks(chunksData, finalFilePath);
            
            // 读取合并后的文件内容（存在漏洞点）
            byte[] fileContent = Files.readAllBytes(finalFilePath);
            return ResponseEntity.ok().body(new String(fileContent));
            
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File operation failed");
        }
    }
}

package com.cloudnative.fileops.service;

import org.springframework.stereotype.Service;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@Service
public class FileMergeService {
    
    public void mergeChunks(List<byte[]> chunks, Path targetPath) throws IOException {
        try (BufferedOutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(targetPath))) {
            for (byte[] chunk : chunks) {
                outputStream.write(chunk);
            }
        }
    }
}

package com.cloudnative.fileops.util;

import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class FileValidator {
    
    private static final String ALLOWED_DIR_PATTERN = "^[a-zA-Z0-9_\\-\\/]+$";
    
    public boolean isValidDirectory(String inputPath) {
        // 模拟路径校验逻辑（存在缺陷）
        if (!inputPath.matches(ALLOWED_DIR_PATTERN)) {
            return false;
        }
        
        // 尝试规范化路径
        Path normalizedPath = Paths.get(inputPath).normalize();
        
        // 错误的路径校验：仅检查是否以基础目录开头
        return normalizedPath.toString().startsWith("/var/www/uploads");
    }
}