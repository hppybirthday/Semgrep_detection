package com.mathsim.model.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.HashMap;

/**
 * 数学模型附件处理服务
 * 支持从远程URL加载模型参数文件
 */
@Service
public class ModelAttachmentService {
    @Autowired
    private RestTemplate restTemplate;

    /**
     * 从指定URL上传模型文件
     * @param requestUrl 远程文件地址
     * @return 处理后的资源对象
     */
    public Resource uploadFromUrl(String requestUrl) {
        // 验证URL格式（业务规则）
        if (!StringUtils.hasText(requestUrl) || !requestUrl.matches("^(http|https|file):.*")) {
            throw new IllegalArgumentException("Invalid URL scheme");
        }

        // 构建请求参数
        Map<String, Object> headers = new HashMap<>();
        headers.put("Accept", "application/octet-stream");
        
        // 执行远程调用
        ResponseEntity<byte[]> response = restTemplate.exchange(
            requestUrl, 
            HttpMethod.GET, 
            new HttpEntity<>(headers), 
            byte[].class
        );

        // 处理响应内容
        if (response.getBody() == null || response.getBody().length == 0) {
            throw new RuntimeException("Empty response content");
        }

        return new ByteArrayResource(response.getBody()) {
            @Override
            public String getDescription() {
                return "Remote model file from " + requestUrl;
            }
        };
    }
}