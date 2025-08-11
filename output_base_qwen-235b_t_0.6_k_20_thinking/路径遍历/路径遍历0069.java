package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

@SpringBootApplication
public class FileServiceApplication {
    private static final Logger logger = Logger.getLogger(FileServiceApplication.class.getName());
    private static final String BASE_DIR = "/var/www/files/";

    public static void main(String[] args) {
        SpringApplication.run(FileServiceApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/files")
    public static class FileController {
        private final FileService fileService = new FileService();

        @GetMapping(value = "/{filename}", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
        public ResponseEntity<byte[]> downloadFile(@PathVariable String filename) throws IOException {
            logger.info("Received file request: " + filename);
            
            if (filename.contains("..")) {
                // 模拟不完整的安全检查
                filename = filename.replaceAll("\\..*\\\\/", "");
            }
            
            byte[] content = fileService.readFileContent(filename);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(content);
        }
    }

    public static class FileService {
        public byte[] readFileContent(String filename) throws IOException {
            // 漏洞点：未正确验证用户输入
            Path filePath = Paths.get(BASE_DIR + filename);
            File file = filePath.toAbsolutePath().normalize().toFile();
            
            if (!file.exists()) {
                throw new IOException("File not found: " + filename);
            }
            
            // 漏洞利用点：允许读取任意文件
            return Files.readAllBytes(file.toPath());
        }
    }
}