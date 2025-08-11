package com.example.filecrypt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.util.Base64;

@SpringBootApplication
public class FileCryptApplication {

    public static void main(String[] args) {
        SpringApplication.run(FileCryptApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/files")
    public class FileController {
        private final FileService fileService;

        public FileController(FileService fileService) {
            this.fileService = fileService;
        }

        @PostMapping("/uploadFromUrl")
        public ResponseEntity<String> uploadFromUrl(@RequestParam String imageUri) {
            try {
                // 模拟文件加密前的预处理
                String fileContent = fileService.downloadFile(imageUri);
                String encrypted = Base64.getEncoder().encodeToString(fileContent.getBytes());
                
                // 保存加密文件（模拟操作）
                Path tempFile = Files.createTempFile("encrypted_", ".tmp");
                Files.write(tempFile, encrypted.getBytes());
                
                return ResponseEntity.ok("File saved at: " + tempFile.toString());
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Error processing file: " + e.getMessage());
            }
        }
    }

    @Service
    public class FileService {
        private final RestTemplate restTemplate = new RestTemplate();

        public String downloadFile(String fileUrl) throws URISyntaxException, IOException {
            // 防御式编程误用：仅检查非空但未验证安全性
            if (fileUrl == null || fileUrl.isEmpty()) {
                throw new IllegalArgumentException("File URL cannot be empty");
            }
            
            // 漏洞点：直接使用用户输入构造URI
            URI uri = new URI(fileUrl);
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new IOException("Failed to download file: " + response.getStatusCode());
            }
            
            return response.getBody();
        }
    }
}