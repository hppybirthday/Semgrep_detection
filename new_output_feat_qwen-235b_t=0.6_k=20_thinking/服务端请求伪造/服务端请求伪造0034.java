package com.example.imageservice.controller;

import com.example.imageservice.service.ImageProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/images")
public class ImageProcessingController {
    @Autowired
    private ImageProcessingService imageProcessingService;

    @PostMapping("/process")
    public String processImage(@RequestParam("imageUrl") String imageUrl) {
        return imageProcessingService.processExternalImage(imageUrl);
    }
}

package com.example.imageservice.service;

import com.example.imageservice.downloader.ImageDownloader;
import com.example.imageservice.util.ImageValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ImageProcessingService {
    @Autowired
    private ImageDownloader imageDownloader;
    @Autowired
    private ImageValidator imageValidator;

    public String processExternalImage(String imageUrl) {
        if (!imageValidator.validateImageUrl(imageUrl)) {
            return "Invalid image URL format";
        }

        byte[] imageData = imageDownloader.downloadImage(imageUrl);
        if (imageData == null || imageData.length == 0) {
            return "Failed to download image";
        }

        return uploadProcessedResult(imageData);
    }

    private String uploadProcessedResult(byte[] imageData) {
        // 模拟图像处理后的上传操作
        return "Processed image size: " + imageData.length + " bytes";
    }
}

package com.example.imageservice.downloader;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class ImageDownloader {
    private final RestTemplate restTemplate;

    public ImageDownloader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] downloadImage(String imageUrl) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "ImageProcessor/1.0");
            HttpEntity<byte[]> entity = new HttpEntity<>((byte[]) null, headers);

            ResponseEntity<byte[]> response = restTemplate.exchange(
                imageUrl,
                HttpMethod.GET,
                entity,
                byte[].class
            );

            return response.getBody();
        } catch (Exception e) {
            // 日志记录和异常处理
            return null;
        }
    }
}

package com.example.imageservice.util;

import org.springframework.stereotype.Service;

@Service
public class ImageValidator {
    public boolean validateImageUrl(String imageUrl) {
        if (imageUrl == null || imageUrl.isEmpty()) {
            return false;
        }

        // 看似严格的URL验证（但存在绕过可能）
        if (!imageUrl.startsWith("https://") && !imageUrl.startsWith("http://")) {
            return false;
        }

        // 更复杂的验证逻辑（但未验证实际主机名）
        return imageUrl.endsWith(".jpg") || 
               imageUrl.endsWith(".png") || 
               imageUrl.endsWith(".gif");
    }
}

package com.example.imageservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}