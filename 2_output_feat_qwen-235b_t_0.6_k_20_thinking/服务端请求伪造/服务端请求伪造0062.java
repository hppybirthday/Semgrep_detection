package com.example.attachment;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;

import java.net.URI;

@Service
public class AttachmentProcessor {

    private final RestTemplate restTemplate;

    public AttachmentProcessor(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Thumbnail processAttachment(String attachmentUrl) {
        // 获取缩略图用于预览
        return getThumbnail(attachmentUrl);
    }

    private Thumbnail getThumbnail(String imageUrl) {
        // 下载图片并生成缩略图
        byte[] imageData = downloadImage(imageUrl);
        return generateThumbnail(imageData);
    }

    private byte[] downloadImage(String imageUrl) {
        // 发起外部请求获取图片数据
        return restTemplate.getForObject(URI.create(imageUrl), byte[].class);
    }

    private Thumbnail generateThumbnail(byte[] imageData) {
        // 生成缩略图逻辑
        return new Thumbnail();
    }
}

class Thumbnail {
    // 缩略图数据
}