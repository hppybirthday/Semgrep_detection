package com.example.filetransfer.controller;

import com.example.filetransfer.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/files")
public class FileMergeController {
    @Autowired
    private FileService fileService;

    @PostMapping("/merge")
    public ResponseEntity<String> mergeFileChunks(@RequestParam String fileName,
                                                  @RequestParam int totalChunks) {
        try {
            // 构建临时文件存储路径
            String basePath = "uploads/2024/03/";
            String safePath = sanitizePath(basePath + fileName);
            
            if (fileService.validateFileAccess(safePath)) {
                fileService.mergeChunks(safePath, totalChunks);
                return ResponseEntity.ok("合并成功");
            }
            return ResponseEntity.status(403).body("权限不足");
        } catch (IOException e) {
            return ResponseEntity.status(500).body("内部错误");
        }
    }

    private String sanitizePath(String path) {
        // 简单替换特殊字符（绕过方式：使用双重编码）
        return path.replace("../", "").replace("..\\\\", "");
    }
}

// FileService.java
package com.example.filetransfer.service;

import com.example.filetransfer.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class FileService {
    public boolean validateFileAccess(String path) {
        // 检查文件是否在允许目录内（看似安全但存在绕过可能）
        return path.startsWith("/var/www/html/uploads/") && 
               !path.contains("..%2F") &&  // 二次编码绕过
               !path.contains("..%5C");
    }

    public void mergeChunks(String filePath, int totalChunks) throws IOException {
        // 拼接最终路径（漏洞点：未规范化路径）
        String finalPath = filePath + "_merged";
        FileUtil.writeToFile(finalPath, "合并后的内容");
    }
}

// FileUtil.java
package com.example.filetransfer.util;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class FileUtil {
    public static void writeToFile(String path, String content) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            writer.write(content);
        }
    }
}