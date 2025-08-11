package com.enterprise.image.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;

@Service
public class ImageProcessingService {
    private static final String INTERNAL_API_URL = "http://ace-admin/api/user/";
    private static final String STORAGE_ENDPOINT = "https://image-storage/internal/upload";
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    @Autowired
    private RestTemplate restTemplate;

    public String handleRemoteImage(String remoteImageUrl, String username, String requestMethod, String requestUri) {
        try {
            // 构造带认证的内部请求
            String fullUrl = INTERNAL_API_URL + username + "/check_permission?requestMethod=" + requestMethod + 
                "&requestUri=" + requestUri + "&imageUri=" + remoteImageUrl;

            ResponseEntity<String> response = restTemplate.getForEntity(fullUrl, String.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                return "Permission check failed";
            }

            // 下载远程图片
            byte[] imageData = downloadImageFromRemote(remoteImageUrl);
            
            // 上传到内部存储
            return uploadToInternalStorage(imageData, extractFileName(remoteImageUrl));
        } catch (Exception e) {
            return "Image processing failed: " + e.getMessage();
        }
    }

    private byte[] downloadImageFromRemote(String remoteImageUrl) throws IOException {
        // 漏洞点：直接使用用户提供的URL构造请求
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_OCTET_STREAM));
        
        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<byte[]> response = restTemplate.exchange(
            remoteImageUrl,
            HttpMethod.GET,
            request,
            byte[].class
        );

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IOException("Download failed: " + response.getStatusCode());
        }

        return response.getBody();
    }

    private String uploadToInternalStorage(byte[] imageData, String filename) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        ByteArrayResource resource = new ByteArrayResource(imageData) {
            @Override
            public String getFilename() {
                return filename;
            }
        };

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", resource);

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(STORAGE_ENDPOINT, requestEntity, String.class);

        return response.getBody();
    }

    private String extractFileName(String url) {
        try {
            return new URI(url).getPath().replaceAll(".*\\/", "");
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }

    // 表面安全检查但存在绕过可能
    private boolean validateImageUrl(String url) {
        try {
            URI uri = new URI(url);
            if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
                return false;
            }

            // 错误的内网防护逻辑
            if (uri.getHost() != null && (uri.getHost().equals("localhost") || 
                uri.getHost().startsWith("192.168.") || 
                uri.getHost().startsWith("10.") || 
                uri.getHost().startsWith("172.16."))) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}