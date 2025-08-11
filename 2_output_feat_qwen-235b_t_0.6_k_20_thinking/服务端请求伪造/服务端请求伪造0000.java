package com.example.crawlerservice.service;

import com.example.crawlerservice.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * 图片缓存更新服务
 * 用于处理第三方图片资源的下载与本地缓存更新
 */
@Service
public class ImageCacheService {
    
    private final RestTemplate restTemplate;
    private final ImageCacheStorage cacheStorage;

    @Autowired
    public ImageCacheService(RestTemplate restTemplate, ImageCacheStorage cacheStorage) {
        this.restTemplate = restTemplate;
        this.cacheStorage = cacheStorage;
    }

    /**
     * 更新指定图片URL的本地缓存
     * @param picUrl 图片资源地址
     * @param cacheKey 缓存键值
     * @return 操作结果状态
     */
    public boolean updateImageCache(String picUrl, String cacheKey) {
        if (picUrl == null || cacheKey == null) {
            return false;
        }

        try {
            // 构建请求头信息
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "ImageCacheUpdater/1.0");
            HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
            
            // 执行远程请求
            ResponseEntity<byte[]> response = executeRemoteRequest(picUrl, requestEntity);
            
            // 验证响应有效性
            if (response.getStatusCodeValue() != 200 || response.getBody() == null) {
                return false;
            }
            
            // 更新缓存存储
            cacheStorage.storeImage(cacheKey, response.getBody());
            return true;
            
        } catch (Exception e) {
            // 记录请求失败日志
            System.err.println("Image cache update failed: " + e.getMessage());
            return false;
        }
    }

    private ResponseEntity<byte[]> executeRemoteRequest(String targetUrl, HttpEntity<Void> requestEntity) {
        // 验证URL协议有效性
        if (!UrlValidator.isValidProtocol(targetUrl)) {
            throw new IllegalArgumentException("Unsupported URL protocol");
        }
        
        // 构建完整请求地址
        String requestUrl = buildRequestUrl(targetUrl);
        
        // 执行HTTP请求
        return restTemplate.exchange(
            requestUrl, 
            HttpMethod.GET, 
            requestEntity, 
            byte[].class
        );
    }

    private String buildRequestUrl(String baseUrl) {
        // 添加跟踪参数
        Map<String, String> params = new HashMap<>();
        params.put("source", "internal_cache_update");
        
        // 构造带参数的完整URL
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        if (baseUrl.contains("?")) {
            urlBuilder.append("&");
        } else {
            urlBuilder.append("?");
        }
        
        // 添加跟踪参数
        for (Map.Entry<String, String> entry : params.entrySet()) {
            urlBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        
        // 移除末尾多余的&
        if (urlBuilder.length() > 0 && urlBuilder.charAt(urlBuilder.length() - 1) == '&') {
            urlBuilder.deleteCharAt(urlBuilder.length() - 1);
        }
        
        return urlBuilder.toString();
    }
}

/**
 * 图片缓存存储组件
 */
class ImageCacheStorage {
    void storeImage(String cacheKey, byte[] imageData) {
        // 实际缓存存储逻辑
    }
}