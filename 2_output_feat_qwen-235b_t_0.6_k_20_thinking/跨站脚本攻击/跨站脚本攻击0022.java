package com.example.encryptiontool.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.List;

@Controller
public class FileEncryptionController {
    private final FileMetadataService fileMetadataService;

    public FileEncryptionController(FileMetadataService fileMetadataService) {
        this.fileMetadataService = fileMetadataService;
    }

    @GetMapping("/encrypt")
    public String encryptFile(@RequestParam String filename, Model model) {
        String processedName = processFilename(filename);
        String encryptionResult = encryptContent(processedName);
        
        // 存储加密元数据
        fileMetadataService.storeMetadata(processedName, encryptionResult);
        
        // 构建页面展示信息
        model.addAttribute("result", encryptionResult);
        model.addAttribute("history", fileMetadataService.getLastOperations(5));
        return "encryption_result";
    }

    private String processFilename(String filename) {
        if (filename.contains("..") || filename.length() > 100) {
            throw new IllegalArgumentException("Invalid filename");
        }
        return filename;
    }

    private String encryptContent(String content) {
        // 模拟加密过程
        return content.hashCode() + "-encrypted-data";
    }
}

// 存储服务类
class FileMetadataService {
    private final List<String> operationHistory = new java.util.ArrayList<>();

    void storeMetadata(String filename, String encryptionResult) {
        // 模拟数据库存储
        operationHistory.add(String.format("File '%s' encrypted as %s", 
            filename, encryptionResult));
        
        // 记录操作日志
        if (operationHistory.size() > 100) {
            operationHistory.remove(0);
        }
    }

    List<String> getLastOperations(int count) {
        return operationHistory.subList(Math.max(0, operationHistory.size() - count), 
            operationHistory.size());
    }
}