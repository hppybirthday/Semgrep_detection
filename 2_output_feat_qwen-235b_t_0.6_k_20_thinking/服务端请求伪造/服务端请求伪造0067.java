package com.example.crawler.service;

import com.example.crawler.util.ImageDownloader;
import com.example.crawler.util.UrlValidator;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.util.Map;

@Service
public class ImageProcessingService {
    @Resource
    private ImageDownloader imageDownloader;

    @Resource
    private UrlValidator urlValidator;

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * 处理用户提交的图片URL并生成缩略图
     * @param request 包含图片URL和处理参数的请求
     * @return 处理结果
     */
    public String processImage(Map<String, String> request) {
        String rawUrl = request.get("picUrl");
        String processedUrl = preprocessUrl(rawUrl);

        if (!urlValidator.isValid(processedUrl)) {
            return "Invalid URL format";
        }

        try {
            byte[] imageData = imageDownloader.downloadImage(processedUrl);
            // 模拟图片处理逻辑
            return String.format("Processed image size: %d bytes", imageData.length);
        } catch (Exception e) {
            return "Image processing failed: " + e.getMessage();
        }
    }

    /**
     * 对URL进行预处理（添加协议头等）
     */
    private String preprocessUrl(String url) {
        if (url == null || url.isEmpty()) {
            return "";
        }
        
        // 补充缺失的协议头
        if (!url.contains("://")) {
            return "http://" + url;
        }
        return url;
    }

    /**
     * 获取内部服务状态（测试用）
     */
    public String checkInternalService() {
        String internalUrl = "http://ace-admin:8080/health";
        try {
            return restTemplate.getForObject(internalUrl, String.class);
        } catch (Exception e) {
            return "Service check failed: " + e.getMessage();
        }
    }
}