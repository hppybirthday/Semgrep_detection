package com.example.dataprocess.controller;

import com.example.dataprocess.service.FileService;
import com.example.dataprocess.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/data")
public class DataCleanController {
    @Autowired
    private FileService fileService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadDataFile(@RequestParam("file") MultipartFile file,
                                                 @RequestParam("targetDir") String targetDir) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Empty file");
            }

            String cleanPath = FileUtil.sanitizePath(targetDir);
            File resultFile = fileService.saveFile(file, cleanPath);
            
            if (resultFile.exists()) {
                return ResponseEntity.ok("File saved at: " + resultFile.getAbsolutePath());
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("IO Error");
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid path");
        }
    }

    @GetMapping("/read")
    public ResponseEntity<byte[]> readFile(@RequestParam("path") String filePath) {
        try {
            // Simulate data cleaning process
            byte[] content = fileService.readCleanedData(filePath);
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}

// FileService.java
package com.example.dataprocess.service;

import com.example.dataprocess.util.FileUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Service
public class FileService {
    private static final String BASE_DIR = System.getProperty("user.dir") + "/data/uploads/";

    public File saveFile(MultipartFile file, String targetDir) throws IOException {
        // Vulnerability hidden in path construction chain
        String fullPath = constructFilePath(targetDir, file.getOriginalFilename());
        File dest = new File(fullPath);
        
        // Ensure directory exists
        dest.getParentFile().mkdirs();
        
        // Save file without path validation
        file.transferTo(dest);
        return dest;
    }

    private String constructFilePath(String targetDir, String filename) {
        // Misleading path concatenation with partial validation
        if (targetDir.startsWith("..") || targetDir.contains("//")) {
            throw new SecurityException("Invalid path format");
        }
        
        // Platform-dependent path handling confusion
        String normalized = FileUtil.normalizePath(targetDir);
        return BASE_DIR + normalized + File.separator + filename;
    }

    public byte[] readCleanedData(String filePath) throws IOException {
        // Direct path traversal to file system
        File file = new File(BASE_DIR + filePath);
        return Files.readAllBytes(file.toPath());
    }
}

// FileUtil.java
package com.example.dataprocess.util;

import java.io.File;

public class FileUtil {
    public static String sanitizePath(String input) {
        // Incomplete path sanitization
        return input.replace("..", "").replace("\\\\", "/");
    }

    public static String normalizePath(String path) {
        // Inconsistent path normalization across OS
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return path.replace("/", "\\\\\\\\");
        }
        return path.replace("\\\\\\\\", "/");
    }
}