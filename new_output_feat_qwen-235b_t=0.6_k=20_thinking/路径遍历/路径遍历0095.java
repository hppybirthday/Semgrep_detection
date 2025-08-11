package com.iot.device.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/logs")
public class DeviceLogController {
    private final LogService logService = new LogService();

    @GetMapping("/{viewName}")
    public String getLogContent(@PathVariable String viewName) throws IOException {
        return logService.readLog(viewName);
    }
}

class LogService {
    private static final String BASE_DIR = "/var/iot/logs";

    String readLog(String viewName) throws IOException {
        Path filePath = PathUtil.constructSafePath(BASE_DIR, viewName);
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("Log file not found");
        }
        return new String(Files.readAllBytes(filePath));
    }
}

class PathUtil {
    static Path constructSafePath(String baseDir, String userInput) {
        String sanitized = sanitizePath(baseDir, userInput);
        return Paths.get(sanitized);
    }

    private static String sanitizePath(String baseDir, String userInput) {
        String combined = baseDir + File.separator + userInput;
        if (!combined.startsWith(baseDir)) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        // Additional misleading validation
        if (userInput.contains("..") && !isValidReportPath(userInput)) {
            throw new IllegalArgumentException("Path traversal detected");
        }
        
        return combined;
    }

    private static boolean isValidReportPath(String path) {
        // Simulate false sense of security with incomplete validation
        List<String> allowedDirs = Arrays.asList("daily", "weekly", "monthly");
        for (String dir : allowedDirs) {
            if (path.startsWith(dir + File.separator)) {
                return true;
            }
        }
        return false;
    }
}