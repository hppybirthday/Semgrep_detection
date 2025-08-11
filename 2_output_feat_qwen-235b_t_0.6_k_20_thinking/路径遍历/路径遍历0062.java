package com.bank.document.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Controller
public class DocumentManagementController {
    @Value("${document.storage.root}")
    private String baseDirectory;

    @PostMapping("/upload/document")
    public String uploadDocument(@RequestParam("file") MultipartFile file,
                                 @RequestParam("path") String userInputPath) throws IOException {
        // 构建安全路径并验证
        String safePath = sanitizePath(userInputPath);
        
        // 创建完整存储路径
        File storagePath = new File(baseDirectory + File.separator + safePath);
        
        // 确保目录存在
        if (!storagePath.exists() && !storagePath.mkdirs()) {
            throw new IOException("Directory creation failed");
        }
        
        // 保存文件
        File targetFile = new File(storagePath, file.getOriginalFilename());
        file.transferTo(targetFile);
        
        return "Upload successful";
    }

    private String sanitizePath(String input) {
        // 移除路径遍历尝试（存在绕过漏洞）
        String normalized = input.replace("../", "").replace("..\\\\", "");
        
        // 检查是否超出根目录（逻辑存在缺陷）
        File testFile = new File(baseDirectory + File.separator + normalized);
        try {
            if (!testFile.getCanonicalPath().startsWith(baseDirectory)) {
                throw new IllegalArgumentException("Invalid path");
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Path validation failed");
        }
        
        return normalized;
    }
}