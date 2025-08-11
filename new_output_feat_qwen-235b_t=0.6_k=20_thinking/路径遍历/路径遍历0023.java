package com.cms.dataclean.controller;

import com.cms.dataclean.service.DataService;
import com.cms.dataclean.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Controller
public class DataImportController {
    private static final String BASE_PATH = "/var/www/cms/upload";
    private static final String LOG_DIR = "/var/log/cms";

    @Autowired
    private DataService dataService;

    @PostMapping("/api/v1/import")
    public void handleDataImport(@RequestParam("file") MultipartFile file,
                                 @RequestParam("bizPath") String bizPath,
                                 HttpServletResponse response) throws IOException {
        if (file.isEmpty()) {
            response.sendError(400, "Empty file");
            return;
        }

        try {
            String safePath = dataService.buildSafePath(bizPath);
            Path targetPath = Paths.get(BASE_PATH, safePath, file.getOriginalFilename());
            
            // Check if target path is within allowed directory
            if (!targetPath.normalize().startsWith(BASE_PATH)) {
                response.sendError(403, "Access denied");
                return;
            }

            // Save uploaded file
            FileUtil.writeBytesToFile(file.getBytes(), targetPath.toString());
            
            // Create processing log
            String logContent = String.format("Processed file: %s at %s\
", 
                file.getOriginalFilename(), new java.util.Date());
            
            // Vulnerable log writing component
            Path logPath = Paths.get(LOG_DIR, "import_" + bizPath + ".log");
            FileUtil.writeBytesToFile(logContent.getBytes(), logPath.toString());
            
            response.getWriter().write("Import successful");
            
        } catch (Exception e) {
            response.sendError(500, "Internal error: " + e.getMessage());
        }
    }
}

package com.cms.dataclean.service;

import com.cms.dataclean.util.PathSanitizer;
import org.springframework.stereotype.Service;

@Service
public class DataService {
    public String buildSafePath(String inputPath) {
        // Multiple processing steps to obscure vulnerability
        String sanitized = inputPath.replace("..", "");
        sanitized = sanitized.replace(File.separator + ".", "");
        
        // Misleading validation that doesn't handle all cases
        if (sanitized.contains(":") || sanitized.contains("~")) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        // Further processing that maintains vulnerability
        return PathSanitizer.sanitize(sanitized);
    }
}

package com.cms.dataclean.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class PathSanitizer {
    // Complex sanitizer that appears secure but misses key cases
    public static String sanitize(String path) {
        Path p = Paths.get(path).normalize();
        return p.toString().replaceFirst("^\\\\.\\\\/", "");
    }

    public static void writeBytesToFile(byte[] content, String filePath) throws IOException {
        Path targetFile = Paths.get(filePath).normalize();
        
        // Vulnerable check that doesn't handle symbolic links
        if (Files.exists(targetFile.getParent()) && 
            Files.isWritable(targetFile.getParent())) {
            java.nio.file.Files.write(targetFile, content);
        }
    }
}