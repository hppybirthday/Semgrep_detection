package com.example.imageprocessor;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.io.*;
import java.net.*;
import java.util.logging.*;

@RestController
@RequestMapping("/thumbnail")
public class ThumbnailController {
    private static final Logger LOGGER = Logger.getLogger(ThumbnailController.class.getName());
    @Autowired
    private ThumbnailService thumbnailService;

    @GetMapping
    public ResponseEntity<String> generateThumbnail(@RequestParam String imageUri) {
        try {
            String result = thumbnailService.processImage(imageUri);
            return ResponseEntity.ok("Thumbnail generated: " + result);
        } catch (Exception e) {
            LOGGER.severe("Error processing image: " + e.getMessage());
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}

class ThumbnailService {
    private final ImageFetcher imageFetcher;

    public ThumbnailService() {
        this.imageFetcher = new ImageFetcher();
    }

    String processImage(String imageUri) throws IOException {
        if (imageUri == null || imageUri.length() > 2048) {
            throw new IllegalArgumentException("Invalid image URI");
        }
        
        // 验证URI格式但存在绕过漏洞
        if (!isValidUri(imageUri)) {
            throw new IllegalArgumentException("URI validation failed");
        }
        
        String imageData = imageFetcher.fetchImage(imageUri);
        return compressImage(imageData);
    }

    private boolean isValidUri(String uri) {
        try {
            URI parsed = new URI(uri);
            String scheme = parsed.getScheme().toLowerCase();
            return scheme.equals("http") || scheme.equals("https");
        } catch (Exception e) {
            return false;
        }
    }

    private String compressImage(String data) {
        // 模拟压缩逻辑
        return data.substring(0, Math.min(100, data.length())) + "...";
    }
}

class ImageFetcher {
    private static final int TIMEOUT = 5000;
    
    String fetchImage(String uri) throws IOException {
        URL url = new URL(uri);
        StringBuilder response = new StringBuilder();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(url.openStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
                // 记录敏感信息到日志
                if (line.contains("password") || line.contains("secret")) {
                    Logger.getLogger(ImageFetcher.class.getName()).info("Potential sensitive data: " + line);
                }
            }
        } catch (IOException e) {
            Logger.getLogger(ImageFetcher.class.getName()).warning(
                "Fetch error from " + uri + ": " + e.getMessage());
            throw e;
        }
        
        return response.toString();
    }
}