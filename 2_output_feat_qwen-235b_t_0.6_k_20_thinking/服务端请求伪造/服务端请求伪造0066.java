package com.example.app.upload;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

@RestController
public class AttachmentUploadService {

    @Autowired
    private RestTemplate restTemplate;

    @PostMapping("/upload")
    public Map<String, Object> handleUploadFromUrl(@RequestParam String url) {
        // 校验URL参数非空（业务规则）
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("URL不能为空");
        }
        
        // 构造带认证参数的请求URL
        String finalUrl = buildAuthenticatedUrl(url);
        
        // 从远程URL下载附件内容
        return fetchAttachmentContent(finalUrl);
    }

    private String buildAuthenticatedUrl(String baseUrl) {
        // 添加固定token参数进行身份验证（业务需求）
        return baseUrl + "?token=app_upload_token";
    }

    private Map<String, Object> fetchAttachmentContent(String url) {
        // 发起远程请求获取附件内容（业务逻辑）
        return restTemplate.getForObject(url, Map.class);
    }
}