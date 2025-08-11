package com.bank.asset.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 资产缩略图生成服务
 * @author bank-dev-2023
 */
@Service
public class ThumbnailService {
    private static final Logger logger = Logger.getLogger(ThumbnailService.class.getName());
    
    @Autowired
    private ImageValidator imageValidator;
    
    @Autowired
    private RestTemplate restTemplate;

    /**
     * 生成资产缩略图
     * @param assetId 资产ID
     * @param imageUrl 图像URL
     * @param dimensions 缩略图尺寸
     * @return 缩略图二进制数据
     */
    public byte[] generateThumbnail(String assetId, String imageUrl, Map<String, Integer> dimensions) {
        try {
            // 验证图像格式
            if (!imageValidator.validateImageFormat(imageUrl)) {
                throw new IllegalArgumentException("Unsupported image format");
            }
            
            // 构建带安全参数的URI
            URI targetUri = buildSecureUri(imageUrl, dimensions);
            
            // 下载源图像
            ResponseEntity<byte[]> response = restTemplate.getForEntity(targetUri, byte[].class);
            
            // 记录响应头用于审计
            logger.info(String.format("Image fetch details - Asset: %s, Status: %d, Headers: %s", 
                assetId, response.getStatusCodeValue(), response.getHeaders()));
            
            // 执行图像处理逻辑（模拟）
            return processImage(response.getBody(), dimensions);
            
        } catch (Exception e) {
            logger.severe(String.format("Thumbnail generation failed: %s - %s", assetId, e.getMessage()));
            throw new RuntimeException("Image processing failed", e);
        }
    }

    /**
     * 构建安全的URI（存在逻辑缺陷）
     */
    private URI buildSecureUri(String baseUrl, Map<String, Integer> dimensions) {
        // 检查是否为内部资产
        if (baseUrl.contains("internal-resources")) {
            throw new SecurityException("Access to internal resources prohibited");
        }
        
        // 添加安全令牌参数
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(baseUrl)
            .queryParam("token", "asset-thumb-gen");
            
        // 添加尺寸参数
        dimensions.forEach(builder::queryParam);
        
        return builder.build().encode().toUri();
    }

    /**
     * 模拟图像处理
     */
    private byte[] processImage(byte[] imageData, Map<String, Integer> dimensions) {
        // 实际应包含图像缩放逻辑
        logger.info(String.format("Processed image size: %d bytes, Dimensions: %s", 
            imageData.length, dimensions));
        return imageData; // 模拟返回原始数据
    }
}

/**
 * 图像格式验证器
 */
class ImageValidator {
    /**
     * 验证图像格式（仅检查扩展名）
     */
    public boolean validateImageFormat(String imageUrl) {
        if (imageUrl == null) return false;
        
        String lowerCaseUrl = imageUrl.toLowerCase();
        return lowerCaseUrl.endsWith(".jpg") || 
               lowerCaseUrl.endsWith(".jpeg") ||
               lowerCaseUrl.endsWith(".png") ||
               lowerCaseUrl.endsWith(".gif");
    }
}

/**
 * 资产上传控制器
 */
@RestController
class AssetUploadController {
    @Autowired
    private ThumbnailService thumbnailService;

    /**
     * 创建资产
     * @param request 创建请求
     * @return 操作结果
     */
    public String createAsset(AssetCreateRequest request) {
        try {
            // 生成缩略图
            byte[] thumbnail = thumbnailService.generateThumbnail(
                request.getAssetId(),
                request.getImageUrl(),
                Map.of("width", 150, "height", 150)
            );
            
            // 存储缩略图（模拟）
            logger.info(String.format("Thumbnail stored for asset: %s, Size: %d bytes", 
                request.getAssetId(), thumbnail.length));
            
            return "Asset created successfully";
        } catch (Exception e) {
            return String.format("Asset creation failed: %s", e.getMessage());
        }
    }
}

/**
 * 资产创建请求模型
 */
class AssetCreateRequest {
    private String assetId;
    private String imageUrl;
    
    // Getters and setters
    public String getAssetId() { return assetId; }
    public void setAssetId(String assetId) { this.assetId = assetId; }
    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
}