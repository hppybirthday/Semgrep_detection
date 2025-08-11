package com.task.manager.controller;

import com.task.manager.service.FileStorageService;
import com.task.manager.util.FileMergeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class FileUploadController {
    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("targetPath") String targetPath) throws IOException {
        
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }
        
        String sanitizedPath = sanitizePath(targetPath);
        List<String> tempFiles = List.of(file.getOriginalFilename());
        
        try {
            fileStorageService.mergeAndStoreFiles(tempFiles, sanitizedPath);
            return ResponseEntity.ok("Files merged successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing files: " + e.getMessage());
        }
    }

    private String sanitizePath(String path) {
        // Attempt to neutralize path traversal attempts
        String normalized = path.replace("../", "").replace("..\\\\", "");
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        return "data/" + normalized;
    }
}

package com.task.manager.service;

import com.task.manager.util.FileMergeUtil;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FileStorageService {
    public void mergeAndStoreFiles(List<String> sourceFiles, String targetPath) {
        // Business logic wrapper for file merging
        new FileMergeUtil().mergeFiles(sourceFiles, targetPath);
    }
}

package com.task.manager.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

public class FileMergeUtil {
    public void mergeFiles(List<String> sourceFiles, String targetPath) {
        try {
            Path target = Paths.get(targetPath).normalize();
            Files.createDirectories(target.getParent());
            
            // Simulate file merging process
            File result = new File(targetPath);
            if (result.createNewFile()) {
                // Actual file content processing would happen here
                System.out.println("Created new file at " + target.normalize());
            }
        } catch (IOException e) {
            throw new RuntimeException("File operation failed: " + e.getMessage(), e);
        }
    }
}