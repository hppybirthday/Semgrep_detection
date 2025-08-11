package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@SpringBootApplication
public class VulnerableApplication {
    // 基础目录配置（本应限制访问范围）
    private static final String BASE_DIR = "/opt/app/plugins/";

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/plugins")
    public static class PluginController {
        
        // 漏洞入口点：文件上传接口
        @PostMapping("/upload")
        public ResponseEntity<String> uploadPlugin(@RequestParam("pluginPath") String pluginPath,
                                                  @RequestParam("file") MultipartFile file) {
            try {
                // 危险的路径拼接（漏洞核心）
                String fullPath = BASE_DIR + pluginPath;
                File targetFile = new File(fullPath);

                // 未进行路径规范化校验
                if (!targetFile.getAbsolutePath().startsWith(BASE_DIR)) {
                    return ResponseEntity.badRequest().body("Invalid path");
                }

                // 实际存在漏洞的文件写入操作
                byte[] bytes = file.getBytes();
                Path path = Paths.get(targetFile.getAbsolutePath());
                Files.write(path, bytes);

                return ResponseEntity.ok("Plugin uploaded successfully");
            } catch (IOException e) {
                return ResponseEntity.status(500).body("Upload failed");
            }
        }

        // 漏洞验证接口
        @GetMapping("/read")
        public ResponseEntity<String> readPlugin(@RequestParam("pluginPath") String pluginPath) {
            try {
                String fullPath = BASE_DIR + pluginPath;
                Path path = Paths.get(fullPath);
                String content = new String(Files.readAllBytes(path));
                return ResponseEntity.ok(content);
            } catch (IOException e) {
                return ResponseEntity.status(500).body("Read failed");
            }
        }
    }
}