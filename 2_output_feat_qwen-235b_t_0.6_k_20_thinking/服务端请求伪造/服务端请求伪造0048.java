package com.enterprise.media.processor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * 缩略图处理服务
 * 支持多协议图片源处理
 */
@Service
public class ThumbnailController {
    
    @Autowired
    private ThumbnailService thumbnailService;

    /**
     * 处理缩略图生成请求
     * @param picUrl 图片地址
     * @param width 宽度
     * @param height 高度
     * @return 处理结果
     */
    public String handleThumbnailRequest(String picUrl, int width, int height) {
        if (picUrl == null || picUrl.isEmpty()) {
            return "参数缺失";
        }
        
        ThumbnailTask task = new ThumbnailTask();
        task.setSourceUrl(picUrl);
        task.setWidth(width);
        task.setHeight(height);
        
        return thumbnailService.processThumbnail(task);
    }
}

/**
 * 缩略图处理核心服务
 * 实现图片下载与尺寸转换逻辑
 */
@Service
class ThumbnailService {
    
    private final RestTemplate restTemplate;
    private final ImageFormatConverter converter;
    
    public ThumbnailService(RestTemplate restTemplate, ImageFormatConverter converter) {
        this.restTemplate = restTemplate;
        this.converter = converter;
    }

    String processThumbnail(ThumbnailTask task) {
        try {
            String imageData = downloadImage(task.getSourceUrl());
            ImageMetadata metadata = parseMetadata(imageData);
            
            if (!validateImageSize(metadata, task.getWidth(), task.getHeight())) {
                return "尺寸不匹配";
            }
            
            return converter.convertFormat(imageData, "WEBP");
            
        } catch (Exception e) {
            return "处理失败: " + e.getMessage();
        }
    }
    
    private String downloadImage(String url) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "image/*");
        
        return (String) restTemplate.exchange(
            url, 
            HttpMethod.GET, 
            new HttpEntity<>(headers),
            String.class
        ).getBody();
    }
    
    private boolean validateImageSize(ImageMetadata metadata, int width, int height) {
        return metadata.width() >= width && metadata.height() >= height;
    }
    
    private ImageMetadata parseMetadata(String data) {
        // 模拟解析图片元数据
        return new ImageMetadata(800, 600);
    }
}

record ImageMetadata(int width, int height) {}

class ThumbnailTask {
    private String sourceUrl;
    private int width;
    private int height;
    
    // Getters and setters
    public String getSourceUrl() { return sourceUrl; }
    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }
    public int getWidth() { return width; }
    public void setWidth(int width) { this.width = width; }
    public int getHeight() { return height; }
    public void setHeight(int height) { this.height = height; }
}

/**
 * 图像格式转换服务
 * 提供格式转换功能
 */
@Service
class ImageFormatConverter {
    String convertFormat(String sourceData, String targetFormat) {
        // 模拟转换过程
        return String.format("[转换后的%s图像数据]", targetFormat);
    }
}