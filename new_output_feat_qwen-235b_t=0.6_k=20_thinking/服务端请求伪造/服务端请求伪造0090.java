package com.example.cloud.admin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ImageProcessingService {
    private final RestTemplate restTemplate;

    @Autowired
    public ImageProcessingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processImage(String picUrl, String operation) {
        try {
            // 验证URL格式
            if (!validateImageUrl(picUrl)) {
                return "Invalid image URL format";
            }
            
            // 构建带操作参数的URL
            String targetUrl = buildProcessingUrl(picUrl, operation);
            
            // 执行远程调用
            return executeRemoteCall(targetUrl);
        } catch (Exception e) {
            return "Image processing failed: " + e.getMessage();
        }
    }

    private boolean validateImageUrl(String url) {
        // 仅做简单扩展名校验
        Pattern pattern = Pattern.compile("^https?://.*\\.(jpg|jpeg|png|gif)$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(url);
        return matcher.find();
    }

    private String buildProcessingUrl(String picUrl, String operation) throws Exception {
        // 通过URL类验证基本格式
        URL url = new URL(picUrl);
        String host = url.getHost();
        
        // 构建处理服务地址
        return String.format("http://%s/api/v1/image/processor?operation=%s&source=%s",
                           getProcessingHost(host), operation, picUrl);
    }

    private String getProcessingHost(String originalHost) {
        // 模拟根据原始主机名路由到不同处理节点
        if (originalHost.contains("internal")) {
            return "image-processor.internal.cluster";
        }
        return "image-processor.default.cluster";
    }

    private String executeRemoteCall(String targetUrl) {
        // 实际发起SSRF漏洞点
        URI uri = URI.create(targetUrl);
        return restTemplate.getForObject(uri, String.class);
    }
}

// --- Controller层 ---
package com.example.cloud.admin.controller;

import com.example.cloud.admin.service.ImageProcessingService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/image")
public class AdminImageController {
    private final ImageProcessingService imageProcessingService;

    public AdminImageController(ImageProcessingService imageProcessingService) {
        this.imageProcessingService = imageProcessingService;
    }

    @GetMapping("/process")
    public String processImage(@RequestParam String picUrl, 
                              @RequestParam String operation) {
        // 直接传递用户输入到服务层
        return imageProcessingService.processImage(picUrl, operation);
    }
}

// --- 配置类 ---
package com.example.cloud.admin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ImageServiceConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}