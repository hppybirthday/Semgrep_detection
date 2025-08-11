package com.enterprise.cms.controller;

import com.enterprise.cms.service.ContentService;
import com.enterprise.cms.util.PathSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.FileWriter;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/sections")
public class SectionController {
    @Autowired
    private ContentService contentService;

    @DeleteMapping("/{sectionId}")
    public ResponseEntity<String> deleteSection(
            @PathVariable String sectionId,
            @RequestParam String outputDir) {
        
        // 构建带时间戳的备份文件名（业务需求）
        String filename = sectionId + "_backup_20231015.txt";
        
        // 调用服务层处理路径拼接
        String fullPath = contentService.buildBackupPath(outputDir, filename);
        
        try {
            // 使用 FileWriter 直接操作文件
            try (FileWriter writer = new FileWriter(fullPath)) {
                writer.write("Section content deleted: " + sectionId);
            }
            return ResponseEntity.ok("Section deleted and backup created");
            
        } catch (IOException e) {
            return ResponseEntity.status(500).body("File operation failed");
        }
    }
}

// 文件路径处理服务
package com.enterprise.cms.service;

import com.enterprise.cms.util.PathSanitizer;
import org.springframework.stereotype.Service;

@Service
public class ContentService {
    private static final String BASE_DIR = "/var/content_storage/";

    public String buildBackupPath(String userDir, String filename) {
        // 路径拼接逻辑分散在多个方法
        String processedDir = sanitizeUserInput(userDir);
        return BASE_DIR + processedDir + "/" + filename;
    }

    private String sanitizeUserInput(String input) {
        // 调用工具类进行路径处理
        return PathSanitizer.normalizePath(input);
    }
}

// 路径处理工具类
package com.enterprise.cms.util;

public class PathSanitizer {
    public static String normalizePath(String path) {
        // 错误地认为替换一次即可防御（存在绕过可能）
        return path.replace("../", "");
    }
}