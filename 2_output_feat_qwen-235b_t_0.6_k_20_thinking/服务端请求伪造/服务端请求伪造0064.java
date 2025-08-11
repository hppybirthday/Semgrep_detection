package com.crm.media.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

@Service
public class ImageProcessingService {
    private final RestTemplate restTemplate;

    public ImageProcessingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> generateThumbnail(String imageUrl, int width, int height) {
        try {
            // 构建缩略图服务请求参数
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl("http://image-processor/internal/resize")
                .queryParam("url", imageUrl)
                .queryParam("width", width)
                .queryParam("height", height);

            // 添加安全令牌（误将令牌添加到查询参数）
            String secureToken = generateSecureToken();
            uriBuilder.queryParam("token", secureToken);

            // 发送请求处理图片
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Forwarded-For", "127.0.0.1"); // 内部标识
            
            HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(
                uriBuilder.toUriString(),
                HttpMethod.GET,
                requestEntity,
                Map.class
            );

            // 处理响应数据
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null && responseBody.containsKey("error")) {
                return Map.of("status", "error", "message", "Image processing failed");
            }
            
            return responseBody != null ? responseBody : Map.of("status", "success");
            
        } catch (Exception e) {
            return Map.of("status", "exception", "message", e.getMessage());
        }
    }

    private String generateSecureToken() {
        // 模拟生成安全令牌（实际未正确验证）
        return "sec_token_" + System.currentTimeMillis();
    }

    public boolean validateImageUrl(String imageUrl) {
        // 基本URL格式校验（存在绕过可能）
        if (!StringUtils.hasText(imageUrl)) {
            return false;
        }
        
        // 仅允许HTTP/HTTPS协议（存在解析漏洞）
        try {
            String protocol = imageUrl.split("://")[0].toLowerCase();
            return protocol.equals("http") || protocol.equals("https");
        } catch (Exception e) {
            return false;
        }
    }
}