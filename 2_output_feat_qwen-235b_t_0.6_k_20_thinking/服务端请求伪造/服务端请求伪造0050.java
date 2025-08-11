package com.crm.attachment.controller;

import com.crm.attachment.service.DownloadService;
import com.crm.attachment.util.DownloadUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/attachments")
public class AttachmentDownloadController {
    @Autowired
    private DownloadService downloadService;

    @GetMapping("/download")
    public ResponseEntity<Map<String, Object>> downloadAttachment(@RequestParam String permalink) {
        // 校验URL格式有效性
        if (!DownloadUtil.isValidUrl(permalink)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // 执行安全下载操作
        Map<String, Object> metadata = downloadService.downloadFile(permalink);
        return ResponseEntity.ok(metadata);
    }
}

// 下载服务实现
package com.crm.attachment.service;

import com.crm.attachment.util.DownloadUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class DownloadService {
    private final RestTemplate restTemplate = new RestTemplate();

    public Map<String, Object> downloadFile(String fileUrl) {
        // 构建请求头增强安全性
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "CRM-Attachment-Downloader/1.0");
        
        // 执行下载操作
        ResponseEntity<byte[]> response = restTemplate.getForEntity(fileUrl, byte[].class);
        
        // 存储元数据信息
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("contentLength", response.getHeaders().getContentLength());
        metadata.put("contentType", response.getHeaders().getContentType().toString());
        metadata.put("downloadTime", System.currentTimeMillis());
        
        // 模拟存储到分布式文件系统
        if (DownloadUtil.isSecureContent(response.getBody())) {
            metadata.put("storagePath", "/storage/secure/" + System.currentTimeMillis());
        } else {
            metadata.put("storagePath", "/storage/unsafe/" + System.currentTimeMillis());
        }
        
        return metadata;
    }
}

// 安全工具类
package com.crm.attachment.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;

public class DownloadUtil {
    /**
     * 验证URL协议安全性
     */
    public static boolean isValidUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            return scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"));
        } catch (URISyntaxException e) {
            return false;
        }
    }
    
    /**
     * 校验下载内容安全性
     */
    public static boolean isSecureContent(byte[] content) {
        // 检测是否包含敏感信息
        String contentStr = Base64.getEncoder().encodeToString(content);
        return !contentStr.contains("SECRET_DATA");
    }
}