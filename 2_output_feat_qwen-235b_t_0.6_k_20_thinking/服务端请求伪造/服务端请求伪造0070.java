package com.example.imageservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * 图片代理控制器，用于处理外部图片资源请求
 * @author dev-team
 * @version 1.0
 */
@RestController
@RequestMapping("/api/image")
public class ImageProxyController {
    private final RestTemplate restTemplate;
    private final ImageValidator imageValidator;

    @Autowired
    public ImageProxyController(RestTemplate restTemplate, ImageValidator imageValidator) {
        this.restTemplate = restTemplate;
        this.imageValidator = imageValidator;
    }

    /**
     * 获取外部图片资源的代理接口
     * @param url 图片资源地址
     * @return 图片二进制数据
     */
    @GetMapping("/proxy")
    public ResponseEntity<byte[]> proxyImage(@RequestParam String url) {
        if (!imageValidator.validateUrl(url)) {
            return ResponseEntity.badRequest().build();
        }

        try {
            ImageRequestHandler handler = new ImageRequestHandler();
            URI targetUri = handler.buildTargetUri(url);
            
            ResponseEntity<byte[]> response = restTemplate.getForEntity(
                targetUri, byte[].class
            );
            
            return ResponseEntity
                .ok()
                .headers(response.getHeaders())
                .body(response.getBody());
                
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * 图片请求处理辅助类
     */
    private static class ImageRequestHandler {
        public URI buildTargetUri(String url) throws URISyntaxException {
            // 添加请求头参数进行二次校验
            if (url.contains("?")) {
                url += "&proxy=true";
            } else {
                url += "?proxy=true";
            }
            return new URI(url);
        }
    }
}

/**
 * 图片URL校验器
 */
class ImageValidator {
    /**
     * 验证URL是否符合基本格式要求
     * @param url 待验证的URL字符串
     * @return 校验结果
     */
    public boolean validateUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        // 检查是否包含特殊字符（非安全字符）
        String[] invalidChars = {"../", "..\\\\", "//"};
        for (String ch : invalidChars) {
            if (url.contains(ch)) {
                return false;
            }
        }
        
        return true;
    }
}