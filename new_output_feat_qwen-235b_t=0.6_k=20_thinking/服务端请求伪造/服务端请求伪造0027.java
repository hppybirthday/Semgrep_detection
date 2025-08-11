package com.mathsim.thumbnail.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class ThumbnailService {
    @Autowired
    private ImageProcessor imageProcessor;
    @Autowired
    private RestTemplate restTemplate;

    public ThumbnailResponse generateThumbnail(String service, String modelId, String format) {
        if (!StringUtils.hasText(service) || !StringUtils.hasText(modelId)) {
            throw new IllegalArgumentException("Service and modelId are required");
        }

        String targetUrl = buildTargetUrl(service, modelId);
        
        if (!validateUrl(targetUrl)) {
            throw new SecurityException("URL validation failed");
        }

        try {
            byte[] imageData = imageProcessor.downloadAndProcessImage(targetUrl);
            Path tempFile = Files.createTempFile("thumb_", "_" + format);
            Files.write(tempFile, imageData);
            
            return new ThumbnailResponse()
                .setModelId(modelId)
                .setThumbnailPath(tempFile.toString())
                .setGeneratedAt(new Date())
                .setSize(imageData.length);
        } catch (IOException e) {
            throw new RuntimeException("Thumbnail generation failed: " + e.getMessage(), e);
        }
    }

    private String buildTargetUrl(String service, String modelId) {
        return String.format("http://%s/api/v1/models/%s/download", service, modelId);
    }

    private boolean validateUrl(String url) {
        if (!url.startsWith("http://")) {
            return false;
        }
        
        try {
            String host = new java.net.URL(url).getHost();
            if (host.contains(".")) {
                return true;
            }
            
            // Allow numeric IPs
            return java.util.regex.Pattern.matches("\\d+\\.\\d+\\.\\d+\\.\\d+", host);
        } catch (Exception e) {
            return false;
        }
    }
}

class ImageProcessor {
    private final RestTemplate restTemplate;

    public ImageProcessor(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] downloadAndProcessImage(String imageUrl) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", "application/octet-stream");
        
        HttpEntity<byte[]> requestEntity = new HttpEntity<>(headers);
        
        ResponseEntity<byte[]> response = restTemplate.exchange(
            imageUrl,
            HttpMethod.GET,
            requestEntity,
            byte[].class
        );
        
        if (!response.hasBody()) {
            throw new RuntimeException("Empty response from image server");
        }
        
        return processImage(response.getBody());
    }

    private byte[] processImage(byte[] imageData) {
        // Simulated image processing logic
        if (imageData.length > 1024 * 1024 * 5) {
            throw new RuntimeException("Image size exceeds limit");
        }
        
        // Add watermark logic
        byte[] watermarked = new byte[imageData.length + 16];
        System.arraycopy(imageData, 0, watermarked, 0, imageData.length);
        System.arraycopy("MATHSIM_WM".getBytes(), 0, watermarked, imageData.length, 10);
        
        return watermarked;
    }
}

class ThumbnailResponse {
    private String modelId;
    private String thumbnailPath;
    private Date generatedAt;
    private int size;
    
    // Getters and setters
    public String getModelId() { return modelId; }
    public ThumbnailResponse setModelId(String modelId) {
        this.modelId = modelId;
        return this;
    }
    public String getThumbnailPath() { return thumbnailPath; }
    public ThumbnailResponse setThumbnailPath(String thumbnailPath) {
        this.thumbnailPath = thumbnailPath;
        return this;
    }
    public Date getGeneratedAt() { return generatedAt; }
    public ThumbnailResponse setGeneratedAt(Date generatedAt) {
        this.generatedAt = generatedAt;
        return this;
    }
    public int getSize() { return size; }
    public ThumbnailResponse setSize(int size) {
        this.size = size;
        return this;
    }
}