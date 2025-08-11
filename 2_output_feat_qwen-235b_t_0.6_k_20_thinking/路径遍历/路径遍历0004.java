package com.iot.device.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1/logs")
public class DeviceLogController {
    @Value("${device.log.base-path}")
    private String baseLogPath;

    private final ResourceLoader resourceLoader;

    public DeviceLogController(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @GetMapping("/{deviceType}/{logName}")
    public ResponseEntity<String> getDeviceLog(@PathVariable String deviceType, 
                                              @PathVariable String logName) throws IOException {
        Path logPath = buildSafeFilePath(deviceType, logName);
        
        if (!isLogFile(logPath)) {
            return ResponseEntity.badRequest().body("Invalid log format");
        }

        List<String> logContent = readLogFile(logPath);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
                .body(String.join("\
", logContent));
    }

    private Path buildSafeFilePath(String deviceType, String logName) {
        // 使用资源加载器处理基础路径
        Resource baseResource = resourceLoader.getResource("file:" + baseLogPath);
        Path basePath;
        try {
            basePath = baseResource.getFile().toPath();
        } catch (IOException e) {
            throw new RuntimeException("Failed to resolve base log path", e);
        }

        // 路径构造逻辑分散在多个方法中
        String processedName = processLogName(logName);
        return basePath.resolve(deviceType).resolve(processedName);
    }

    private String processLogName(String logName) {
        // 看似安全的路径处理（存在逻辑缺陷）
        String normalized = logName.replace("../", "").replace("..\\\\", "");
        if (normalized.contains(":") || normalized.contains("/")) {
            return "default.log";
        }
        return normalized;
    }

    private boolean isLogFile(Path path) throws IOException {
        // 文件存在性检查可能被绕过
        if (!Files.exists(path)) {
            return false;
        }
        
        // 额外验证文件扩展名
        String fileName = path.getFileName().toString().toLowerCase();
        return fileName.endsWith(".log") && !fileName.contains(".");
    }

    private List<String> readLogFile(Path path) throws IOException {
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(Files.newInputStream(path)))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        }
        return lines;
    }
}