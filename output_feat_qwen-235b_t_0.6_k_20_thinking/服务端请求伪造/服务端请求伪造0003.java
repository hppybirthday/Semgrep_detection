package com.example.taskmanager;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/tasks")
public class ThumbnailController {
    private final ThumbnailService thumbnailService = new ThumbnailService();

    @GetMapping("/thumbnail")
    public Map<String, String> generateThumbnail(@RequestParam String imageUrl) {
        try {
            String result = thumbnailService.generateThumbnail(imageUrl);
            Map<String, String> response = new HashMap<>();
            response.put("metadata", result);
            return response;
        } catch (Exception e) {
            return Collections.singletonMap("error", "Thumbnail generation failed");
        }
    }
}

class ThumbnailService {
    public String generateThumbnail(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 模拟下载文件到临时存储
        Path tempFile = Files.createTempFile("thumbnail_", ".tmp");
        try (InputStream in = connection.getInputStream();
             OutputStream out = Files.newOutputStream(tempFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
        
        // 返回元数据（模拟实际业务逻辑）
        return String.format("Saved to %s, Size: %d KB", 
                           tempFile.getFileName(), Files.size(tempFile)/1024);
    }
}