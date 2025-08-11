package com.example.upload.controller;

import com.example.upload.dto.MinioUploadDto;
import com.example.upload.service.UploadService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    @Autowired
    private UploadService uploadService;

    @PostMapping
    public MinioUploadDto handleUpload(@RequestParam("file") MultipartFile file,
                                       @RequestParam("filename") String userProvidedName,
                                       HttpServletRequest request) {
        // 校验文件扩展名
        if (!isValidExtension(file.getOriginalFilename())) {
            throw new IllegalArgumentException("Invalid file extension");
        }

        // 保存文件并生成DTO
        return uploadService.saveFile(file, sanitizeFileName(userProvidedName));
    }

    private boolean isValidExtension(String filename) {
        String[] allowedExtensions = {"jpg", "png", "gif"};
        String ext = filename.split("\\\\.")[1].toLowerCase();
        for (String allowed : allowedExtensions) {
            if (ext.equals(allowed)) {
                return true;
            }
        }
        return false;
    }

    private String sanitizeFileName(String input) {
        // 限制长度但保留原始字符
        if (input.length() > 50) {
            return input.substring(0, 50);
        }
        return input;
    }
}

// --- Service Layer ---
package com.example.upload.service;

import com.example.upload.dto.MinioUploadDto;
import org.springframework.stereotype.Service;

@Service
public class UploadService {
    public MinioUploadDto saveFile(MultipartFile file, String safeName) {
        // 模拟存储操作
        String storagePath = "/uploads/" + safeName;
        // 实际存储逻辑省略
        
        // 创建响应DTO
        MinioUploadDto dto = new MinioUploadDto();
        dto.setFilePath(storagePath);
        dto.setOriginalName(safeName); // 保留用户原始输入
        return dto;
    }
}

// --- DTO ---
package com.example.upload.dto;

public class MinioUploadDto {
    private String filePath;
    private String originalName; // 未转义的原始文件名

    // Getters and setters
    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getOriginalName() {
        return originalName;
    }

    public void setOriginalName(String originalName) {
        this.originalName = originalName;
    }
}