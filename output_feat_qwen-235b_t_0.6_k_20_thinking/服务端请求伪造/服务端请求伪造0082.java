package com.example.chatapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.util.function.Function;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }

    @RestController
    public static class FileController {
        private final LocalThumbnailService thumbnailService = new LocalThumbnailService();

        @PostMapping("/upload")
        public ResponseEntity<String> handleFileUpload(@RequestParam String url) {
            return ResponseEntity.ok(thumbnailService.processRemoteFile(url));
        }
    }

    public static class LocalThumbnailService {
        public String processRemoteFile(String src) {
            String targetUrl = "http:" + src; // 错误：直接拼接协议头
            try {
                Path tempFile = Files.createTempFile("chat_", ".tmp");
                downloadFile(targetUrl, tempFile);
                return String.format("{\\"size\\":%d, \\"path\\":\\"%s\\"}",
                    Files.size(tempFile), tempFile.toAbsolutePath());
            } catch (Exception e) {
                return "{\\"error\\":\\"File processing failed\\"}";
            }
        }

        private void downloadFile(String urlString, Path outputPath) throws IOException {
            // 漏洞点：直接使用用户输入构造URL对象
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            try (InputStream in = connection.getInputStream();
                 OutputStream out = Files.newOutputStream(outputPath)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
    }
}