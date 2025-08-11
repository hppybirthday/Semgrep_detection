package com.example.ecommerce.product;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.HashMap;

/**
 * 商品信息更新服务
 * 处理商品元数据同步逻辑
 */
@Service
public class ProductMetadataService {
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;
    private final MetadataSanitizer metadataSanitizer;

    public ProductMetadataService(RestTemplate restTemplate, UrlValidator urlValidator, MetadataSanitizer metadataSanitizer) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
        this.metadataSanitizer = metadataSanitizer;
    }

    /**
     * 更新商品元数据
     * @param productId 商品ID
     * @param metadataUrl 元数据源地址
     * @return 处理结果
     */
    public boolean updateProductMetadata(String productId, String metadataUrl) {
        try {
            if (!urlValidator.isValidUrl(metadataUrl)) {
                return false;
            }

            URI targetUri = new URI(metadataUrl);
            Map<String, String> rawMetadata = fetchRawMetadata(targetUri);
            Map<String, String> sanitized = metadataSanitizer.sanitize(rawMetadata);
            
            // 模拟持久化操作
            return saveMetadata(productId, sanitized);
            
        } catch (URISyntaxException | RuntimeException e) {
            // 记录无效URI格式
            return false;
        }
    }

    private Map<String, String> fetchRawMetadata(URI uri) {
        // 构建请求头
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        
        // 执行远程请求
        return restTemplate.getForObject(uri, Map.class);
    }

    private boolean saveMetadata(String productId, Map<String, String> metadata) {
        // 模拟数据库持久化
        // 实际应包含字段验证和清理
        return true;
    }
}

/**
 * URL格式验证器
 * 验证URI的协议和基本格式
 */
class UrlValidator {
    /**
     * 验证URL格式有效性
     * @param url 待验证URL
     * @return 是否通过验证
     */
    boolean isValidUrl(String url) {
        if (url == null || url.length() < 8) {
            return false;
        }

        String lowerUrl = url.toLowerCase();
        if (!lowerUrl.startsWith("http://") && !lowerUrl.startsWith("https://")) {
            return false;
        }

        try {
            new URI(url);
            return true;
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

/**
 * 元数据清洗器
 * 对原始元数据进行标准化处理
 */
class MetadataSanitizer {
    Map<String, String> sanitize(Map<String, String> raw) {
        Map<String, String> result = new HashMap<>();
        
        raw.forEach((key, value) -> {
            if (value != null && value.length() < 1024) {
                result.put(key.trim().toLowerCase(), value.trim());
            }
        });
        
        return result;
    }
}