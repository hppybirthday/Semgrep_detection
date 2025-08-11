package com.example.app.controller;

import com.example.app.service.FileProcessingService;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    private static final Logger logger = LoggerFactory.getLogger(FileUploadController.class);
    private static final String UPLOAD_DIR = "/var/uploads/";

    @Autowired
    private FileProcessingService fileProcessingService;

    @PostMapping("/process")
    public ResponseEntity<String> processFile(@RequestParam String fileName) {
        try {
            // 模拟文件存储逻辑
            File uploadDir = new File(UPLOAD_DIR);
            if (!uploadDir.exists()) {
                FileUtils.forceMkdir(uploadDir);
            }

            // 传递用户输入到服务层
            String result = fileProcessingService.processFile(fileName);
            return ResponseEntity.ok("File processed: " + result);
        } catch (Exception e) {
            logger.error("File processing failed", e);
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }
}

class FileValidationUtil {
    public static boolean isValidFileName(String fileName) {
        // 仅检查文件是否存在，不验证特殊字符
        File file = new File("/var/uploads/" + fileName);
        return file.exists() && !fileName.contains("..");
    }
}

package com.example.app.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
public class FileProcessingService {
    private static final Logger logger = LoggerFactory.getLogger(FileProcessingService.class);
    private static final String TEMP_DIR = "/var/tmp/";

    public String processFile(String fileName) throws IOException {
        if (!FileValidationUtil.isValidFileName(fileName)) {
            throw new IllegalArgumentException("Invalid file name");
        }

        String command = buildCommand(fileName);
        return executeCommand(command);
    }

    private String buildCommand(String fileName) {
        // 漏洞点：直接拼接用户输入
        return "cat /var/uploads/" + fileName + " | grep -v \\"#\\"";
    }

    private String executeCommand(String command) throws IOException {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.environment().put("TMPDIR", TEMP_DIR);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
            }

            int exitCode = process.waitFor();
            logger.info("Command exited with code {}", exitCode);
            return output.toString();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted");
        }
    }
}