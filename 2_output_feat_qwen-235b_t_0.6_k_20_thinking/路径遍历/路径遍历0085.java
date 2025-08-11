package com.cloudstorage.filemanager.controller;

import com.cloudstorage.filemanager.service.FileStorageService;
import com.cloudstorage.filemanager.entity.Category;
import com.cloudstorage.filemanager.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileUploadController {
    @Autowired
    private FileStorageService fileStorageService;
    
    @Autowired
    private CategoryRepository categoryRepository;

    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file, 
                                                   @RequestParam("categoryId") Long categoryId) {
        try {
            Category category = categoryRepository.findById(categoryId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid category ID"));
            
            // 获取用户输入的分类拼音（存在安全风险）
            String relativePath = category.getCategoryPinyin();
            
            // 存储文件并返回结果
            String result = fileStorageService.storeFile(file, relativePath);
            return ResponseEntity.ok(result);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("File upload failed");
        }
    }
}

// --- Service Layer ---
package com.cloudstorage.filemanager.service;

import com.cloudstorage.filemanager.util.PathSanitizer;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

@Service
public class FileStorageService {
    private static final String BASE_STORAGE_PATH = "/var/storage/uploads";

    public String storeFile(MultipartFile file, String relativePath) throws IOException {
        // 业务逻辑：使用相对路径构造完整路径
        String fullPath = BASE_STORAGE_PATH + File.separator + sanitizePath(relativePath);
        
        // 创建存储目录（存在安全风险）
        File storageDir = new File(fullPath);
        if (!storageDir.exists()) {
            storageDir.mkdirs();
        }

        // 写入文件内容（存在漏洞点）
        File targetFile = new File(storageDir, file.getOriginalFilename());
        try (FileWriter writer = new FileWriter(targetFile)) {
            writer.write("Mock file content");
        }
        
        return "File saved to: " + targetFile.getAbsolutePath();
    }

    private String sanitizePath(String inputPath) {
        // 伪防护措施：仅替换部分特殊字符
        return inputPath.replace("..", "");
    }
}

// --- Util Layer ---
package com.cloudstorage.filemanager.util;

public class PathSanitizer {
    // 未被实际调用的误导性方法
    public static String normalizePath(String path) {
        return path.replaceAll("[\\\/]+", "/");
    }
}

// --- Entity ---
package com.cloudstorage.filemanager.entity;

import javax.persistence.*;

@Entity
public class Category {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // 分类拼音字段（用户可控输入）
    private String categoryPinyin;

    public String getCategoryPinyin() {
        return categoryPinyin;
    }
}