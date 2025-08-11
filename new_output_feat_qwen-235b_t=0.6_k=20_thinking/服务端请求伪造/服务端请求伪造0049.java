package com.example.imageservice.controller;

import com.example.imageservice.service.ImageProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/image")
public class ImageProcessingController {
    private final ImageProcessingService imageProcessingService;

    @Autowired
    public ImageProcessingController(ImageProcessingService imageProcessingService) {
        this.imageProcessingService = imageProcessingService;
    }

    @GetMapping("/thumbnail")
    public ResponseEntity<byte[]> generateThumbnail(@RequestParam String picUrl, @RequestParam int width, @RequestParam int height) {
        try {
            BufferedImage thumbnail = imageProcessingService.generateThumbnail(picUrl, width, height);
            return ResponseEntity.ok()
                    .header("Content-Type", "image/jpeg")
                    .body(ImageIO.writeBytes(thumbnail, "JPEG"));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}

package com.example.imageservice.service;

import com.example.imageservice.util.ImageValidator;
import com.example.imageservice.util.NetworkUtil;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.CompletableFuture;

@Service
public class ImageProcessingService {
    private static final int MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB

    public BufferedImage generateThumbnail(String picUrl, int width, int height) throws IOException {
        if (!ImageValidator.isValidSize(width, height)) {
            throw new IllegalArgumentException("Invalid dimensions");
        }

        URL validatedUrl = validateImageUrl(picUrl);
        BufferedImage originalImage = downloadImage(validatedUrl);
        
        // 模拟复杂的图像处理流程
        return processImage(originalImage, width, height);
    }

    private URL validateImageUrl(String picUrl) throws IOException {
        URL url = NetworkUtil.normalizeUrl(picUrl);
        
        if (!NetworkUtil.isHttpsUrl(url)) {
            throw new IllegalArgumentException("Only HTTPS URLs are allowed");
        }
        
        if (NetworkUtil.isInternalNetwork(url)) {
            throw new IllegalArgumentException("Access to internal resources is restricted");
        }
        
        return url;
    }

    private BufferedImage downloadImage(URL url) throws IOException {
        // 使用自定义网络客户端替代传统URL.openStream()
        return NetworkUtil.fetchImageWithTimeout(url, 5000);
    }

    private BufferedImage processImage(BufferedImage image, int width, int height) {
        // 实际图像处理逻辑
        return new BufferedImage(width, height, image.getType());
    }
}

package com.example.imageservice.util;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI;

public class NetworkUtil {
    public static URL normalizeUrl(String picUrl) throws IOException {
        try {
            return new URI(picUrl).toURL();
        } catch (Exception e) {
            throw new IOException("Invalid URL format");
        }
    }

    public static boolean isHttpsUrl(URL url) {
        return "https".equalsIgnoreCase(url.getProtocol());
    }

    public static boolean isInternalNetwork(URL url) {
        String host = url.getHost().toLowerCase();
        // 误判localhost的检查
        return host.equals("localhost") || 
               host.startsWith("127.") || 
               host.matches("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}") ||
               host.matches("172\\.(1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3}") ||
               host.matches("192\\.168\\.\\d{1,3}\\.\\d{1,3}");
    }

    public static BufferedImage fetchImageWithTimeout(URL url, int timeoutMs) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        
        // 错误地信任所有响应码
        if (connection.getResponseCode() >= 400) {
            throw new IOException("Image fetch failed with code: " + connection.getResponseCode());
        }
        
        return ImageIO.read(connection.getInputStream());
    }
}

package com.example.imageservice.util;

public class ImageValidator {
    public static boolean isValidSize(int width, int height) {
        return width > 0 && height > 0 && width <= 10000 && height <= 10000;
    }
}