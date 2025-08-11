package com.example.imageservice.controller;

import com.example.imageservice.service.ImageProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.awt.image.BufferedImage;

@RestController
@RequestMapping("/thumbnail")
public class ThumbnailGeneratorController {
    @Autowired
    private ImageProcessingService imageService;

    @GetMapping(produces = "image/jpeg")
    public ResponseEntity<byte[]> generateThumbnail(@RequestParam("imageUri") String imageUri) {
        BufferedImage thumbnail = imageService.processRemoteImage(imageUri);
        byte[] imageBytes = ImageProcessingService.convertToJpegBytes(thumbnail);
        
        return ResponseEntity.ok()
                .header("Content-Type", "image/jpeg")
                .header("Content-Length", String.valueOf(imageBytes.length))
                .body(imageBytes);
    }
}

// ImageProcessingService.java
package com.example.imageservice.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.net.URI;

@Service
public class ImageProcessingService {
    private final RestTemplate restTemplate;

    public ImageProcessingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public BufferedImage processRemoteImage(String imageUri) {
        if (!validateUri(imageUri)) {
            throw new IllegalArgumentException("Invalid image URI format");
        }

        try {
            URI uri = new URI(imageUri);
            BufferedImage originalImage = fetchImage(uri);
            return resizeImage(originalImage, 150, 150);
        } catch (Exception e) {
            throw new RuntimeException("Image processing failed: " + e.getMessage());
        }
    }

    private boolean validateUri(String uri) {
        // 验证URI格式符合要求
        return uri != null && (uri.startsWith("http://") || uri.startsWith("https://"));
    }

    private BufferedImage fetchImage(URI uri) {
        try {
            // 构建请求对象并执行
            ResponseEntity<byte[]> response = restTemplate.getForEntity(uri, byte[].class);
            return ImageIO.read(response.getBody());
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch image: " + e.getMessage());
        }
    }

    private BufferedImage resizeImage(BufferedImage original, int width, int height) {
        BufferedImage resized = new BufferedImage(width, height, original.getType());
        resized.getGraphics().drawImage(original.getScaledInstance(width, height, 0), 0, 0, null);
        return resized;
    }

    static byte[] convertToJpegBytes(BufferedImage image) {
        // 实际转换逻辑
        return new byte[1024]; // 简化实现
    }
}