package com.example.securitydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@SpringBootApplication
public class FileEncryptionApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileEncryptionApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@Controller
@RequestMapping("/api/encrypt")
class FileEncryptionController {
    private final RestTemplate restTemplate;

    public FileEncryptionController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping
    @ResponseBody
    public ResponseEntity<String> encryptFile(@RequestParam String fileUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL进行远程请求
            ResponseEntity<String> response = restTemplate.getForEntity(fileUrl, String.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                String fileContent = response.getBody();
                // 简单的加密操作（实际应使用安全的加密算法）
                String encryptedContent = Base64.getEncoder().encodeToString(
                    fileContent.getBytes(StandardCharsets.UTF_8)
                );
                return ResponseEntity.ok("Encrypted: " + encryptedContent);
            }
            return ResponseEntity.status(response.getStatusCode()).body("Failed to fetch file");
        } catch (Exception e) {
            // 防御式编程中的日志记录
            System.err.println("Encryption error: " + e.getMessage());
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    // 模拟文件下载的另一种实现方式（同样存在漏洞）
    private String downloadFile(String urlString) throws IOException {
        URL url = new URL(urlString);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            return content.toString();
        }
    }
}
