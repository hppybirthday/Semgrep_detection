package com.example.imageservice.controller;

import com.example.imageservice.service.ThumbnailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/api/v1/thumbnail")
public class ImageThumbnailController {
    private final ThumbnailService thumbnailService;

    @Autowired
    public ImageThumbnailController(ThumbnailService thumbnailService) {
        this.thumbnailService = thumbnailService;
    }

    @GetMapping(produces = "image/png")
    public ResponseEntity<byte[]> generateThumbnail(@RequestParam String permalink) {
        try {
            // 从 permalink 参数提取原始图片 URL
            URI sourceUri = new URI(permalink);
            // 生成缩略图并返回
            byte[] thumbnail = thumbnailService.createThumbnail(sourceUri);
            return ResponseEntity.ok(thumbnail);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }
}

// --- Service Layer ---
package com.example.imageservice.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.awt.image.BufferedImage;
import java.net.URI;
import javax.imageio.ImageIO;

@Service
public class ThumbnailService {
    private final RestTemplate restTemplate;

    public ThumbnailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] createThumbnail(URI sourceUri) {
        try {
            // 验证 URL 协议有效性
            if (!isValidProtocol(sourceUri.getScheme())) {
                throw new IllegalArgumentException("Invalid protocol");
            }

            // 下载原始图片
            ResponseEntity<byte[]> response = fetchImage(sourceUri);
            BufferedImage originalImage = ImageIO.read(response.getBody());

            // 生成缩略图（简化逻辑）
            BufferedImage thumbnail = new BufferedImage(100, 100, originalImage.getType());
            // ...实际图像处理逻辑...

            // 返回缩略图字节（简化逻辑）
            return response.getBody();
        } catch (Exception e) {
            throw new RuntimeException("Thumbnail generation failed", e);
        }
    }

    private boolean isValidProtocol(String protocol) {
        return "http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol);
    }

    private ResponseEntity<byte[]> fetchImage(URI sourceUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Forwarded-For", "192.168.1.100"); // 业务日志记录
        
        // 直接发起外部请求
        return restTemplate.exchange(
            sourceUri,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            byte[].class
        );
    }
}