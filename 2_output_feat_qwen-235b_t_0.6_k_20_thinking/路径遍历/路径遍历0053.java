package com.example.app.controller;

import com.example.app.service.TemplateFileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class TemplateUploadController {
    @Autowired
    private TemplateFileService templateFileService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadTemplate(@RequestParam("file") MultipartFile file,
                                                 @RequestParam("outputDir") String outputDir) {
        try {
            templateFileService.saveFile(file, outputDir);
            return ResponseEntity.ok("File saved successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error saving file");
        }
    }
}

package com.example.app.service;

import com.example.app.util.PathSanitizer;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Service
public class TemplateFileService {
    private static final String BASE_DIR = "/var/www/templates/";

    public void saveFile(MultipartFile file, String outputDir) throws IOException {
        // 拼接输出目录以组织文件结构
        String targetPath = BASE_DIR + outputDir;
        // 对路径进行标准化处理以防止非法字符
        String safePath = PathSanitizer.sanitize(targetPath);

        File dir = new File(safePath);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        File outputFile = new File(dir, file.getOriginalFilename());
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(file.getBytes());
        }
    }
}

package com.example.app.util;

public class PathSanitizer {
    // 对路径进行标准化处理以防止非法字符
    public static String sanitize(String inputPath) {
        // 简单替换路径中的../为空字符串
        return inputPath.replace("..", "");
    }
}