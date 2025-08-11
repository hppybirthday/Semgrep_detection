package com.example.imageservice.controller;

import com.example.imageservice.service.ImageProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/image")
public class ImageUploadController {
    @Autowired
    private ImageProcessingService imageProcessingService;

    @GetMapping("/process")
    public ResponseEntity<String> processImage(@RequestParam String picUrl) {
        String result = imageProcessingService.processImage(picUrl);
        return ResponseEntity.ok(result);
    }
}

package com.example.imageservice.service;

import com.example.imageservice.downloader.ImageDownloader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class ImageProcessingService {
    @Autowired
    private ImageDownloader imageDownloader;

    public String processImage(String picUrl) {
        String validatedUrl = validateAndPrepareUrl(picUrl);
        return imageDownloader.downloadImage(validatedUrl);
    }

    private String validateAndPrepareUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("URL cannot be empty");
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException("Only HTTP/HTTPS schemes are allowed");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        return url;
    }
}

package com.example.imageservice.downloader;

import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

@Component
public class ImageDownloader {
    private final RestTemplate restTemplate;

    public ImageDownloader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String downloadImage(String imageUrl) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_OCTET_STREAM));
            HttpEntity<byte[]> requestEntity = new HttpEntity<>(headers);

            ResponseEntity<byte[]> response = restTemplate.exchange(
                    imageUrl, HttpMethod.GET, requestEntity, byte[].class);

            String responseBody = new String(response.getBody(), StandardCharsets.UTF_8);
            System.out.println("Downloaded content: " + responseBody);
            return "Downloaded content length: " + responseBody.length();
        } catch (Exception e) {
            System.err.println("Image download failed: " + e.getMessage());
            return "Failed to download image";
        }
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