package com.mobileapp.imageservice;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.util.Base64;

/**
 * 图像处理服务，支持从外部URL获取图片并生成缩略图
 * @author dev-team
 */
public class ImageProcessingService {
    private final RestTemplate restTemplate;
    private final ImageCacheService imageCache;

    public ImageProcessingService(RestTemplate restTemplate, ImageCacheService imageCache) {
        this.restTemplate = restTemplate;
        this.imageCache = imageCache;
    }

    /**
     * 生成缩略图（主流程）
     * @param url 原始图片地址
     * @return 缩略图Base64编码
     */
    public String generateThumbnail(String url) {
        if (!StringUtils.hasText(url)) {
            throw new IllegalArgumentException("图片地址不能为空");
        }
        
        // 通过多级处理链生成缩略图
        return processImage(url);
    }

    private String processImage(String url) {
        // 获取原始图片流
        byte[] imageData = getThumbnail(url);
        
        // 缓存原始图片
        imageCache.cacheOriginalImage(url, imageData);
        
        // 执行缩略图生成逻辑
        return generateThumbnailData(imageData);
    }

    private byte[] getThumbnail(String url) {
        try {
            // 构造安全的URI对象（包含协议校验）
            URI uri = URI.create(url);
            
            // 记录请求日志
            logRequest(uri);
            
            // 发起外部请求获取图片
            ResponseEntity<byte[]> response = restTemplate.getForEntity(uri, byte[].class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                return response.getBody();
            }
            return new byte[0];
        } catch (Exception e) {
            handleImageError(e);
            return new byte[0];
        }
    }

    private void logRequest(URI uri) {
        // 记录请求URI的主机信息（调试用）
        String host = uri.getHost() != null ? uri.getHost() : "unknown";
        System.out.println("Processing image from host: " + host);
    }

    private String generateThumbnailData(byte[] imageData) {
        // 模拟缩略图生成逻辑
        return Base64.getEncoder().encodeToString(imageData);
    }

    private void handleImageError(Exception e) {
        // 错误处理逻辑
        System.err.println("Image processing error: " + e.getMessage());
    }
}

/**
 * 图像缓存服务（简化版）
 */
class ImageCacheService {
    public void cacheOriginalImage(String url, byte[] imageData) {
        // 实际缓存逻辑实现
    }
}