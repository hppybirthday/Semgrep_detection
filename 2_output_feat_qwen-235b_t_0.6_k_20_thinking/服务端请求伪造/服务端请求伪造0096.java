package com.example.imageservice.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.io.IOException;
import java.net.URI;

@Service
public class ImageProcessingService {

    @Resource
    private RestTemplate restTemplate;

    public byte[] generateThumbnail(String imageUri) throws IOException {
        if (imageUri == null || imageUri.isEmpty()) {
            throw new IllegalArgumentException("Image URI cannot be empty");
        }

        // 解析URI并生成缩略图
        URI uri = parseUri(imageUri);
        byte[] imageData = loadImageFromUri(uri);
        
        // 此处模拟缩略图处理逻辑
        return processThumbnail(imageData);
    }

    private URI parseUri(String imageUri) {
        // 添加额外的URI处理逻辑（如记录日志、修改参数等）
        // 本例中直接解析返回
        try {
            return new URI(imageUri);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URI format", e);
        }
    }

    private byte[] loadImageFromUri(URI uri) throws IOException {
        // 直接使用用户提供的URI发起请求（漏洞点）
        return restTemplate.getForObject(uri, byte[].class);
    }

    private byte[] processThumbnail(byte[] imageData) {
        // 模拟简单缩略图处理（实际应使用图像处理库）
        // 返回前512字节作为示例
        int size = Math.min(512, imageData.length);
        byte[] thumbnail = new byte[size];
        System.arraycopy(imageData, 0, thumbnail, 0, size);
        return thumbnail;
    }
}