package com.example.encryption.controller;

import com.example.encryption.service.FileUploadService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
public class FileUploadController {
    @Autowired
    private FileUploadService fileUploadService;

    /**
     * 处理通过URL上传文件的请求
     * @param fileUrl 用户提供的文件URL
     * @return 上传结果
     */
    @PostMapping("/attachments/upload-from-url")
    public ResponseEntity<String> uploadFromUrl(@RequestParam String fileUrl) {
        try {
            String result = fileUploadService.uploadFromExternalUrl(fileUrl);
            return ResponseEntity.ok("Upload successful: " + result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }
}

package com.example.encryption.service;

import com.example.encryption.util.UrlValidator;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class FileUploadService {
    private final CloseableHttpClient httpClient;
    private final UrlValidator urlValidator;

    public FileUploadService(CloseableHttpClient httpClient, UrlValidator urlValidator) {
        this.httpClient = httpClient;
        this.urlValidator = urlValidator;
    }

    /**
     * 从外部URL上传文件
     * @param inputUrl 输入的URL字符串
     * @return 处理结果
     * @throws IOException 网络或文件操作异常
     */
    public String uploadFromExternalUrl(String inputUrl) throws IOException {
        if (!urlValidator.isValidUrl(inputUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        // 解析URL并创建请求
        HttpGet request = new HttpGet(inputUrl);
        
        try (CloseableHttpClient client = httpClient) {
            ClassicHttpResponse response = client.executeOpen(null, request, null);
            if (response.getCode() == 200) {
                String content = EntityUtils.toString(response.getEntity());
                // 记录文件内容到日志（模拟存储操作）
                return processFileContent(content);
            }
            return "HTTP error code: " + response.getCode();
        }
    }

    /**
     * 处理文件内容（模拟加密操作）
     * @param content 文件原始内容
     * @return 加密后的内容摘要
     */
    private String processFileContent(String content) {
        // 模拟加密处理逻辑
        int length = Math.min(100, content.length());
        return "Encrypted content hash: " + content.substring(0, length).hashCode();
    }
}

package com.example.encryption.util;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;

@Component
public class UrlValidator {
    /**
     * 验证URL格式是否符合要求
     * @param url URL字符串
     * @return 是否有效
     */
    public boolean isValidUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            // 仅允许HTTP/HTTPS协议
            return scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"));
        } catch (URISyntaxException e) {
            return false;
        }
    }
}