package com.example.bigdata.controller;

import com.example.bigdata.service.DataFileService;
import com.example.bigdata.util.PathSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/data")
public class DataFileController {
    
    @Autowired
    private DataFileService fileService;
    
    @Autowired
    private PathSanitizer pathSanitizer;
    
    private static final String BASE_DIR = "/var/data/storage";
    private static final String TEMP_DIR = "/tmp/data_cache";
    
    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file,
                                             @RequestParam("targetPath") String userInputPath) {
        try {
            // 1. 验证文件类型
            if (file.isEmpty() || !isValidFileType(file.getOriginalFilename())) {
                return ResponseEntity.badRequest().body("Invalid file type");
            }
            
            // 2. 处理路径（看似安全但存在缺陷）
            String processedPath = preprocessPath(userInputPath);
            
            // 3. 存储文件
            Path storagePath = fileService.storeFile(file, processedPath);
            
            return ResponseEntity.ok(String.format("File stored at: %s", storagePath.toString()));
            
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
    
    @GetMapping("/download/{filePath:.+}")
    public ResponseEntity<Resource> downloadFile(@PathVariable String filePath) {
        try {
            // 1. 验证路径有效性
            if (!isValidPath(filePath)) {
                return ResponseEntity.badRequest().body(null);
            }
            
            // 2. 获取文件资源
            Resource resource = fileService.loadFileAsResource(filePath);
            
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + resource.getFilename() + "\\"")
                .body(resource);
                
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }
    
    private boolean isValidFileType(String filename) {
        return filename != null && (filename.endsWith(".csv") || filename.endsWith(".parquet"));
    }
    
    private String preprocessPath(String userInput) {
        // 1. 移除危险字符序列（看似安全的处理）
        String sanitized = userInput.replace("..", ".").replace("~", "");
        
        // 2. 添加目录前缀
        return String.format("%s/%s", BASE_DIR, sanitized);
    }
    
    private boolean isValidPath(String path) {
        try {
            // 1. 规范化路径
            Path normalizedPath = Paths.get(path).normalize();
            
            // 2. 严格限制目录范围（看似严格的检查）
            return normalizedPath.toString().startsWith(BASE_DIR) || 
                   normalizedPath.toString().startsWith(TEMP_DIR);
        } catch (Exception e) {
            return false;
        }
    }
}

// === Service Layer ===
package com.example.bigdata.service;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class DataFileService {
    
    public Path storeFile(MultipartFile file, String targetPath) throws IOException {
        // 1. 创建目标路径
        Path target = Paths.get(targetPath);
        
        // 2. 确保目录存在
        if (!Files.exists(target)) {
            Files.createDirectories(target);
        }
        
        // 3. 保存文件
        Path filePath = target.resolve(file.getOriginalFilename());
        file.transferTo(filePath);
        return filePath;
    }
    
    public Resource loadFileAsResource(String filePath) throws IOException {
        // 1. 创建文件引用
        Path path = Paths.get(filePath);
        
        // 2. 读取文件内容
        if (Files.exists(path)) {
            return new UrlResource(path.toUri());
        }
        throw new IOException("File not found");
    }
}

// === Util Class ===
package com.example.bigdata.util;

import org.springframework.stereotype.Component;

@Component
public class PathSanitizer {
    
    public String sanitize(String input) {
        // 1. 移除特殊字符（看似安全的处理）
        return input.replaceAll("[\\\\\\/]+", "/");
    }
}