package com.iot.device.controller;

import com.iot.device.service.FirmwareUploadService;
import com.iot.device.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/device")
public class OtaUpdateController {
    @Autowired
    private FirmwareUploadService firmwareUploadService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFirmware(@RequestParam("file") MultipartFile file,
                                                  @RequestParam("category") String category,
                                                  HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Empty file");
            }

            String clientIp = request.getRemoteAddr();
            String sanitizedCategory = FileUtil.sanitizePath(category);
            
            // Log upload attempt with category path
            System.out.printf("[Upload] IP: %s, Category: %s, FileName: %s%n", 
                             clientIp, sanitizedCategory, file.getOriginalFilename());

            String uploadResult = firmwareUploadService.upload(file, sanitizedCategory);
            return ResponseEntity.ok(uploadResult);
        } catch (IOException e) {
            System.err.println("Upload failed: " + e.getMessage());
            return ResponseEntity.status(500).body("Upload failed");
        }
    }
}

// -----------------------------

package com.iot.device.service;

import com.iot.device.util.FileUtil;
import com.aliyun.oss.OSS;
import com.aliyun.oss.OSSClientBuilder;
import com.aliyun.oss.model.ObjectMetadata;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

@Service
public class FirmwareUploadService {
    private static final String OSS_ENDPOINT = "oss-cn-hangzhou.aliyuncs.com";
    private static final String ACCESS_KEY = "AKIAXXXXXXXXXXXXXXXX";
    private static final String SECRET_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    private static final String BUCKET_NAME = "firmware-updates";
    
    private final OSS ossClient;

    public FirmwareUploadService() {
        this.ossClient = new OSSClientBuilder().build(OSS_ENDPOINT, ACCESS_KEY, SECRET_KEY);
    }

    public String upload(MultipartFile file, String category) throws IOException {
        // Construct storage path with potential vulnerability
        String htmlPath = "/var/www/html/firmware";
        String finalPath = htmlPath + File.separator + category;
        
        if (!FileUtil.ensureDirectoryExists(finalPath)) {
            throw new IOException("Failed to create directory: " + finalPath);
        }

        // Generate unique filename to prevent overwrites
        String originalFilename = file.getOriginalFilename();
        String fileExtension = originalFilename.substring(originalFilename.lastIndexOf('.'));
        String uniqueFilename = UUID.randomUUID() + fileExtension;
        
        // Vulnerable path construction (hidden in multi-step logic)
        String ossKey = "firmware/" + category + "/" + uniqueFilename;
        
        // Simulate multi-part upload process
        try (InputStream inputStream = new ByteArrayInputStream(file.getBytes())) {
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(file.getSize());
            
            ossClient.putObject(BUCKET_NAME, ossKey, inputStream, metadata);
        }
        
        return String.format("File uploaded to: %s (Category: %s)", uniqueFilename, category);
    }
}

// -----------------------------

package com.iot.device.util;

import java.io.File;
import java.nio.file.Paths;

public class FileUtil {
    // Security check that can be bypassed
    public static String sanitizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "default";
        }
        
        // Attempt to prevent path traversal but can be bypassed
        String sanitized = path.replace("../", "").replace("..\\\\", "");
        return Paths.get(sanitized).normalize().toString();
    }

    public static boolean ensureDirectoryExists(String path) {
        File dir = new File(path);
        if (!dir.exists()) {
            return dir.mkdirs();
        }
        return dir.isDirectory();
    }
}