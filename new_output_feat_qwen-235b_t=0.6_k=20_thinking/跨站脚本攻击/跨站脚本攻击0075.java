package com.example.filesecurity.controller;

import com.example.filesecurity.exception.FileSecurityException;
import com.example.filesecurity.service.FileEncryptionService;
import com.example.filesecurity.util.FileValidator;
import com.example.filesecurity.model.FileEntity;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
public class FileUploadController {
    @Autowired
    private FileEncryptionService encryptionService;

    @PostMapping("/upload")
    public ResponseEntity<Map<String, String>> uploadFile(
            @RequestParam("filename") String filename,
            @RequestParam("content") String content,
            @RequestParam(value = "description", required = false) String description) {
        
        Map<String, String> response = new HashMap<>();
        try {
            // 模拟文件加密流程
            if (!FileValidator.isValidFileType(filename)) {
                throw new FileSecurityException("Invalid file type: " + filename);
            }
            
            FileEntity fileEntity = new FileEntity();
            fileEntity.setFilename(filename);
            fileEntity.setDescription(description);
            fileEntity.setEncryptedContent(encryptionService.encrypt(content));
            
            response.put("status", "success");
            response.put("message", "File " + filename + " uploaded successfully");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("status", "error");
            // 漏洞点：直接拼接用户输入到错误消息
            response.put("message", "Upload failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}

// 漏洞辅助类
package com.example.filesecurity.exception;

public class FileSecurityException extends Exception {
    public FileSecurityException(String message) {
        super(message);
    }
}

package com.example.filesecurity.util;

public class FileValidator {
    public static boolean isValidFileType(String filename) {
        // 模拟扩展名校验
        String[] allowedExtensions = {"txt", "docx", "xlsx"};
        for (String ext : allowedExtensions) {
            if (filename.toLowerCase().endsWith("." + ext)) {
                return true;
            }
        }
        return false;
    }
}

package com.example.filesecurity.model;

public class FileEntity {
    private String filename;
    private String description;
    private String encryptedContent;
    
    // Getters and setters
    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getEncryptedContent() { return encryptedContent; }
    public void setEncryptedContent(String encryptedContent) { this.encryptedContent = encryptedContent; }
}

package com.example.filesecurity.service;

import org.springframework.stereotype.Service;

@Service
public class FileEncryptionService {
    public String encrypt(String content) {
        // 模拟加密逻辑
        return "ENCRYPTED_" + content.hashCode();
    }
}

// 安全配置（误导性代码）
package com.example.filesecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {
    @Bean
    public XssSanitizer xssSanitizer() {
        return new XssSanitizer();
    }
}

class XssSanitizer {
    // 未被实际调用的误导性安全类
    public String sanitize(String input) {
        return input.replaceAll("[<>]", "");
    }
}