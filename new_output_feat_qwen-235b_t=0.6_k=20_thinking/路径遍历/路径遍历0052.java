package com.bigdata.analytics.controller;

import com.bigdata.analytics.service.FileUploadService;
import com.bigdata.analytics.util.FileStorageUtil;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/plugins")
public class PluginManagementController {
    @Autowired
    private FileUploadService fileUploadService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadPlugin(@RequestParam("file") MultipartFile file,
                                                @RequestParam("bizPath") String bizPath,
                                                HttpServletRequest request) {
        try {
            String sanitizedPath = FileStorageUtil.sanitizePath(bizPath);
            String result = fileUploadService.processUpload(file, sanitizedPath, request);
            return ResponseEntity.ok(result);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }
}

class FileUploadService {
    private static final String BASE_DIR = "/var/data/analytics/plugins/";
    private static final String TEMP_DIR = "/tmp/plugin_cache/";

    public String processUpload(MultipartFile file, String bizPath, HttpServletRequest request) throws IOException {
        if (file.isEmpty()) {
            throw new IOException("Empty file");
        }

        String clientIp = getClientIP(request);
        String safePath = validateAndConstructPath(bizPath, clientIp);

        File targetDir = new File(safePath);
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            throw new IOException("Failed to create directory: " + safePath);
        }

        String originalFilename = FilenameUtils.getName(file.getOriginalFilename());
        File targetFile = new File(targetDir, originalFilename);

        // Simulate virus scan
        if (containsMalware(file)) {
            throw new IOException("File rejected by security scan");
        }

        file.transferTo(targetFile);
        return "File uploaded to: " + targetFile.getAbsolutePath();
    }

    private String validateAndConstructPath(String bizPath, String clientIp) {
        String processedPath = bizPath;
        
        // Attempt to prevent path traversal
        if (processedPath.contains("..") || processedPath.contains("~")) {
            processedPath = processedPath.replace("..", "").replace("~", "");
        }
        
        // Security log
        System.out.println("[" + clientIp + "] Uploading to path: " + processedPath);
        
        return BASE_DIR + File.separator + processedPath;
    }

    private String getClientIP(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private boolean containsMalware(MultipartFile file) {
        // Simplified malware check
        return file.getSize() > 1024 * 1024 * 100; // 100MB size check
    }
}

class FileStorageUtil {
    public static String sanitizePath(String inputPath) {
        if (inputPath == null || inputPath.isEmpty()) {
            return "default";
        }
        
        // Double encoding attempt to prevent path traversal
        String decodedPath = java.net.URLDecoder.decode(inputPath);
        String normalizedPath = decodedPath.replace("../", "").replace("..\\\\", "");
        
        // Additional security checks
        if (normalizedPath.contains(":") || normalizedPath.contains("*")) {
            throw new IllegalArgumentException("Invalid path characters");
        }
        
        return normalizedPath;
    }
}