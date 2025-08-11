package com.example.fileencryptor.controller;

import com.example.fileencryptor.service.FileEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class FileUploadController {
    @Autowired
    private FileEncryptionService encryptionService;

    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") byte[] fileData,
                                                    @RequestParam("prefix") String prefix,
                                                    @RequestParam("suffix") String suffix) {
        String baseDir = "/var/secure_storage/" + java.time.LocalDate.now() + "/" + UUID.randomUUID();
        
        // 初始化加密配置
        String encryptionKey = System.getenv("ENCRYPTION_KEY");
        if (encryptionKey == null || encryptionKey.isEmpty()) {
            return ResponseEntity.status(500).body("Encryption key not configured");
        }

        try {
            // 执行加密并存储
            String result = encryptionService.encryptAndStore(fileData, baseDir, prefix, suffix, encryptionKey);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}

// --- Service Layer ---
package com.example.fileencryptor.service;

import com.example.fileencryptor.util.PathResolver;
import org.springframework.stereotype.Service;

@Service
public class FileEncryptionService {
    private final PathResolver pathResolver;

    public FileEncryptionService(PathResolver pathResolver) {
        this.pathResolver = pathResolver;
    }

    public String encryptAndStore(byte[] data, String baseDir, String prefix, String suffix, String encryptionKey) {
        String resolvedPath = pathResolver.resolvePath(baseDir, prefix, suffix);
        
        // 模拟AES加密过程
        byte[] encryptedData = performAesEncryption(data, encryptionKey);
        
        // 存储加密文件（简化实现）
        return saveToFileSystem(resolvedPath, encryptedData);
    }

    private byte[] performAesEncryption(byte[] data, String key) {
        // 实际应使用安全的加密库
        return data; // 仅模拟
    }

    private String saveToFileSystem(String path, byte[] data) {
        // 模拟文件存储操作
        return String.format("Stored at: %s (size: %d)", path, data.length);
    }
}

// --- Utility Class ---
package com.example.fileencryptor.util;

import org.springframework.stereotype.Component;

@Component
public class PathResolver {
    public String resolvePath(String baseDir, String prefix, String suffix) {
        // 合并路径段
        String combined = baseDir + "/" + prefix + "/" + suffix;
        return normalizePath(combined);
    }

    private String normalizePath(String path) {
        // 简化的路径清理（存在缺陷）
        return path.replace("//", "/").replace("\\\\\\\\", "/");
    }
}