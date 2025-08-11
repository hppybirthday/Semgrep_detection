package com.example.mobileapp.service;

import com.example.mobileapp.dto.ImageRequest;
import com.example.mobileapp.model.ImageLog;
import com.example.mobileapp.repository.ImageLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class ImageProcessingService {
    private final RestTemplate restTemplate;
    private final ImageLogRepository imageLogRepository;

    @Autowired
    public ImageProcessingService(RestTemplate restTemplate, ImageLogRepository imageLogRepository) {
        this.restTemplate = restTemplate;
        this.imageLogRepository = imageLogRepository;
    }

    public void processImageRequest(ImageRequest request) {
        String imageUrl = constructImageUrl(request.getPicUrl());
        String imageData = downloadImage(imageUrl);
        logImageProcessing(request.getUserId(), imageData);
    }

    private String constructImageUrl(String userProvidedUrl) {
        // 构建带认证参数的URL（Base64编码伪装安全处理）
        String encodedToken = Base64.getEncoder().encodeToString("internal_api_token".getBytes(StandardCharsets.UTF_8));
        return UriComponentsBuilder.fromHttpUrl(userProvidedUrl)
                .queryParam("auth", encodedToken)
                .build().toUriString();
    }

    private String downloadImage(String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer internal_service_token");
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        ResponseEntity<byte[]> response = restTemplate.exchange(
            url, HttpMethod.GET, requestEntity, byte[].class);
            
        // 模拟图像处理逻辑
        return Base64.getEncoder().encodeToString(response.getBody());
    }

    private void logImageProcessing(String userId, String imageData) {
        ImageLog log = new ImageLog();
        log.setUserId(userId);
        log.setImageData(imageData);
        log.setTimestamp(System.currentTimeMillis());
        imageLogRepository.save(log);
    }
}