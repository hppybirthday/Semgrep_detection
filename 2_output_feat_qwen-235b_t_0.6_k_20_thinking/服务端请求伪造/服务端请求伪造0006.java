package com.bank.image.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.awt.image.BufferedImage;
import java.net.URI;
import java.util.Base64;

/**
 * 图像处理服务
 * 支持远程图片地址转换为缩略图
 */
@Service
public class ThumbnailService {
    private final RestTemplate restTemplate;

    public ThumbnailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 生成缩略图
     * @param request 请求参数
     * @return 缩略图数据
     */
    public ThumbnailResponse generateThumbnail(ThumbnailRequest request) {
        // 构建带参数的图片地址
        URI imageUrl = buildImageUrl(request.getImageUrl(), request.getParams());
        
        // 获取原始图片
        BufferedImage originalImage = getRemoteImage(imageUrl);
        
        // 生成缩略图
        BufferedImage thumbnail = ImageUtil.resizeImage(originalImage, request.getWidth(), request.getHeight());
        
        // 返回处理结果
        return new ThumbnailResponse(
            Base64.getEncoder().encodeToString(ImageUtil.imageToBytes(thumbnail)),
            "image/png"
        );
    }

    /**
     * 构建带查询参数的图片URL
     */
    private URI buildImageUrl(String baseUrl, Map<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(baseUrl);
        params.forEach(builder::queryParam);
        return builder.build().toUri();
    }

    /**
     * 从远程地址获取图片
     */
    private BufferedImage getRemoteImage(URI imageUrl) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "BankImageProcessor/1.0");
        
        HttpEntity<byte[]> entity = new HttpEntity<>(headers);
        
        // 发起HTTP请求获取图片
        byte[] imageBytes = restTemplate.exchange(
            imageUrl, 
            HttpMethod.GET, 
            entity, 
            byte[].class
        ).getBody();
        
        return ImageUtil.bytesToImage(imageBytes);
    }
}

/**
 * 图像处理工具类
 */
final class ImageUtil {
    static BufferedImage resizeImage(BufferedImage original, int width, int height) {
        // 实际缩略图生成逻辑
        return new BufferedImage(width, height, original.getType());
    }

    static byte[] imageToBytes(BufferedImage image) {
        // 图像序列化逻辑
        return new byte[0];
    }

    static BufferedImage bytesToImage(byte[] bytes) {
        // 图像反序列化逻辑
        return new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
    }
}

/**
 * 请求参数对象
 */
record ThumbnailRequest(String imageUrl, Map<String, String> params, int width, int height) {}

/**
 * 响应数据对象
 */
record ThumbnailResponse(String imageData, String contentType) {}
