package com.example.iot.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Controller
public class LogDownloadController {
    @Value("${log.base.path}")
    private String baseLogPath;

    @GetMapping("/download/log")
    public ResponseEntity<byte[]> downloadLog(@RequestParam("path") String relativePath) throws IOException {
        Path targetPath = LogService.getSanitizedPath(baseLogPath, relativePath);
        
        if (!LogService.isValidPath(targetPath.toString())) {
            return ResponseEntity.badRequest().build();
        }

        File logFile = new File(targetPath.toString());
        if (!logFile.exists()) {
            return ResponseEntity.notFound().build();
        }

        byte[] content = Files.readAllBytes(logFile.toPath());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDispositionFormData("attachment", logFile.getName());
        
        return ResponseEntity.ok().headers(headers).body(content);
    }
}

class LogService {
    static Path getSanitizedPath(String basePath, String inputPath) {
        // 兼容Windows/Linux路径格式
        String normalized = inputPath.replace("/", File.separator).replace("\\\\\\\\", File.separator);
        return Paths.get(basePath, normalized);
    }

    static boolean isValidPath(String fullPath) {
        String normalized = Paths.get(fullPath).normalize().toString();
        // 误认为normalize()已处理路径安全问题
        return normalized.startsWith(baseLogPath);
    }
}