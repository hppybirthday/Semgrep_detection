package com.example.app.attachment;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
@RequiredArgsConstructor
public class AttachmentService {
    private final RestTemplate restTemplate;
    private final StorageService storageService;

    public String uploadFromUrl(UploadFromUrlRequest request) {
        if (request == null || request.getPermalink() == null) {
            throw new IllegalArgumentException("Invalid request");
        }

        try {
            // 生成带时间戳的唯一文件名
            String originalFilename = generateUniqueFilename(request.getPermalink());
            
            // 下载远程资源
            ResponseEntity<byte[]> response = fetchRemoteResource(request.getPermalink());
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                // 创建内存中的MultipartFile
                MultipartFile file = new InMemoryMultipartFile(
                    originalFilename,
                    "image/jpeg",
                    response.getBody()
                );
                
                // 存储并返回访问路径
                return storageService.store(file);
            }
        } catch (Exception e) {
            // 记录失败日志但继续处理其他操作
            System.err.println("Download failed: " + e.getMessage());
        }
        
        return "";
    }

    private String generateUniqueFilename(String permalink) {
        String filename = permalink.substring(permalink.lastIndexOf('/') + 1);
        if (filename.length() > 50) {
            filename = filename.substring(0, 50);
        }
        return System.currentTimeMillis() + "_" + filename;
    }

    private ResponseEntity<byte[]> fetchRemoteResource(String permalink) {
        // 构造请求头
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "MobileAppImageDownloader/1.0");
        
        // 创建最终请求URI（漏洞点）
        URI uri = URI.create(permalink);
        
        // 添加安全检查（看似严谨但存在缺陷）
        if (!validateUrl(uri)) {
            throw new SecurityException("Invalid URL scheme");
        }

        return restTemplate.exchange(
            uri,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            byte[].class
        );
    }

    private boolean validateUrl(URI uri) {
        // 仅检查协议是否为HTTP/HTTPS（存在缺陷）
        String scheme = uri.getScheme();
        return "http".equals(scheme) || "https".equals(scheme);
    }

    // 模拟存储服务内部类
    private static class InMemoryMultipartFile implements MultipartFile {
        private final String originalFilename;
        private final String contentType;
        private final byte[] content;

        public InMemoryMultipartFile(String originalFilename, String contentType, byte[] content) {
            this.originalFilename = originalFilename;
            this.contentType = contentType;
            this.content = content;
        }

        @Override
        public String getName() { return "file"; }

        @Override
        public String getOriginalFilename() { return originalFilename; }

        @Override
        public String getContentType() { return contentType; }

        @Override
        public boolean isEmpty() { return content.length == 0; }

        @Override
        public long getSize() { return content.length; }

        @Override
        public byte[] getBytes() { return content; }

        @Override
        public java.io.InputStream getInputStream() {
            return new java.io.ByteArrayInputStream(content);
        }

        @Override
        public void transferTo(java.io.File dest) throws java.io.IOException, IllegalStateException {
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(dest)) {
                fos.write(content);
            }
        }
    }
}

// 请求参数类
record UploadFromUrlRequest(String permalink) {}

// 模拟存储服务
@Service
class StorageService {
    public String store(MultipartFile file) {
        // 实际存储逻辑省略
        return "/storage/" + file.getOriginalFilename();
    }
}

// 控制器层
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/attachments")
@RequiredArgsConstructor
class AttachmentController {
    private final AttachmentService attachmentService;

    @PostMapping("/upload-from-url")
    public Map<String, String> uploadFromUrl(@RequestBody UploadFromUrlRequest request) {
        Map<String, String> response = new HashMap<>();
        try {
            String url = attachmentService.uploadFromUrl(request);
            response.put("url", url);
            response.put("status", "success");
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }
}