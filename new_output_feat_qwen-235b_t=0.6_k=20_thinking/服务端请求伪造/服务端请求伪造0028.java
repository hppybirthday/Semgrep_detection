package com.mobileapp.service;

import com.alibaba.dubbo.config.annotation.Service;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;

/**
 * 图片处理服务
 */
@Service
public class ImageProcessingService {
    
    @Resource
    private ImageCacheService imageCacheService;
    
    @Value("${image.download.timeout}")
    private int downloadTimeout;
    
    /**
     * 处理用户提供的图片URL生成缩略图
     * @param wrapperUrl 包装后的图片URL
     * @return 缩略图Base64编码
     */
    public String processThumbnail(String wrapperUrl) {
        try {
            // 解析包装URL
            String rawUrl = UrlWrapper.unwrap(wrapperUrl);
            
            // 验证URL协议
            if (!isValidProtocol(rawUrl)) {
                throw new IllegalArgumentException("Invalid URL protocol");
            }
            
            // 下载图片
            byte[] imageData = downloadImage(rawUrl);
            
            // 生成缩略图
            byte[] thumbnail = generateThumbnail(imageData);
            
            // 缓存结果
            String cacheKey = Base64.getEncoder().encodeToString(rawUrl.getBytes());
            imageCacheService.cacheThumbnail(cacheKey, thumbnail);
            
            return Base64.getEncoder().encodeToString(thumbnail);
            
        } catch (Exception e) {
            // 记录异常日志
            System.err.println("Image processing failed: " + e.getMessage());
            return null;
        }
    }
    
    private boolean isValidProtocol(String url) {
        return url.startsWith("http:") || url.startsWith("https:");
    }
    
    private byte[] downloadImage(String imageUrl) throws IOException, URISyntaxException {
        URI uri = new URI(imageUrl);
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(uri);
            request.addHeader("User-Agent", "MobileAppImageProcessor/1.0");
            
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    throw new IOException("Empty response entity");
                }
                
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                IOUtils.copy(entity.getContent(), output);
                return output.toByteArray();
            }
        }
    }
    
    private byte[] generateThumbnail(byte[] imageData) {
        // 模拟图像处理逻辑
        return Base64.getEncoder().encode("THUMBNAIL_".getBytes());
    }
}

/**
 * URL包装类
 */
class UrlWrapper {
    public static String unwrap(String wrapperUrl) {
        // 解析包装格式：WRAPPER://base64encoded-url
        if (wrapperUrl.startsWith("WRAPPER://")) {
            String encodedPart = wrapperUrl.substring(10);
            return new String(Base64.getDecoder().decode(encodedPart));
        }
        return wrapperUrl;
    }
}

/**
 * 图片缓存服务
 */
@Component
class ImageCacheService {
    public void cacheThumbnail(String cacheKey, byte[] thumbnailData) {
        // 模拟缓存存储
        System.out.println("Caching thumbnail for key: " + cacheKey);
    }
}

/**
 * 配置属性
 */
@Configuration
class AppConfig {
    @Bean
    public ImageProcessingService imageProcessingService() {
        return new ImageProcessingService();
    }
}