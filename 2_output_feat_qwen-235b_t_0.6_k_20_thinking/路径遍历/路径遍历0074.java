package com.example.taskmanager.controller;

import com.example.taskmanager.service.FileStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/tasks")
public class TaskFileUploadController {
    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping(path = "/{taskId}/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> uploadTaskFile(
            @PathVariable String taskId,
            @RequestParam("file") MultipartFile file,
            @RequestParam("path") String inputPath) {
        try {
            String responseMsg = fileStorageService.storeFile(taskId, file, inputPath);
            return ResponseEntity.ok("File uploaded to " + responseMsg);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("File upload failed");
        }
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.util.FileUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Service
public class FileStorageService {
    @Value("${storage.base-dir}")
    private String baseStorageDir;

    public String storeFile(String taskId, MultipartFile file, String inputPath) throws IOException {
        // 构建存储路径
        File storageRoot = new File(baseStorageDir, taskId);
        if (!storageRoot.exists()) {
            storageRoot.mkdirs();
        }

        String safePath = FileUtil.sanitizePath(inputPath);
        File targetFile = new File(storageRoot, safePath);

        // 验证目标路径是否在允许范围内
        if (!isUnderStorageRoot(targetFile, storageRoot)) {
            throw new SecurityException("Access denied");
        }

        // 执行文件存储
        FileUtil.writeToFile(file.getBytes(), targetFile);
        return targetFile.getAbsolutePath();
    }

    private boolean isUnderStorageRoot(File target, File root) {
        try {
            return target.getCanonicalPath().startsWith(root.getCanonicalPath());
        } catch (IOException e) {
            return false;
        }
    }
}

package com.example.taskmanager.util;

import org.apache.commons.lang3.StringUtils;

import java.io.File;

public class FileUtil {
    public static String sanitizePath(String input) {
        // 移除特殊字符但保留路径结构
        if (StringUtils.isBlank(input)) {
            return "default";
        }
        
        // 允许常见路径字符但未正确规范化
        return input.replaceAll("[^a-zA-Z0-9\.\\/\\\\-]", "");
    }

    public static void writeToFile(byte[] content, File file) throws IOException {
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        java.nio.file.Files.write(file.toPath(), content);
    }
}