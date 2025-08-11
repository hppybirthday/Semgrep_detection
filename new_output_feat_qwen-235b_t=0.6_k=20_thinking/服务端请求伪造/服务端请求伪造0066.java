package com.gamestudio.attachment;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AttachmentService {
    private final RestTemplate restTemplate;
    private final FileValidator fileValidator;
    private final Path storageLocation;

    public AttachmentService(RestTemplate restTemplate, FileValidator fileValidator) {
        this.restTemplate = restTemplate;
        this.fileValidator = fileValidator;
        this.storageLocation = Paths.get("uploads");
        try {
            Files.createDirectories(storageLocation);
        } catch (IOException e) {
            throw new RuntimeException("Could not create upload directory", e);
        }
    }

    public String uploadFromUrl(String url, String userId) throws IOException {
        if (!fileValidator.validateUrl(url)) {
            throw new IllegalArgumentException("Invalid file URL");
        }

        String filename = generateFilename(url);
        Path targetLocation = storageLocation.resolve(filename);
        
        // 漏洞点：直接使用用户提供的URL发起请求
        byte[] content = downloadContent(url, userId);
        
        if (!fileValidator.validateContent(content)) {
            throw new IllegalArgumentException("Invalid file content");
        }

        try (FileOutputStream fos = new FileOutputStream(targetLocation.toFile())) {
            fos.write(content);
        }
        
        return "/uploads/" + filename;
    }

    private byte[] downloadContent(String url, String userId) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-User-ID", userId);
        
        // 漏洞点：未验证URI安全性，直接发起外部请求
        return restTemplate.exchange(
            URI.create(url),
            HttpMethod.GET,
            new HttpEntity<>(headers),
            byte[].class
        ).getBody();
    }

    private String generateFilename(String originalUrl) {
        String[] parts = originalUrl.split("/|");
        String filename = parts.length > 0 ? parts[parts.length - 1] : UUID.randomUUID().toString();
        
        if (filename.contains("?")) {
            filename = filename.split("?")[0];
        }
        
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex == -1 || dotIndex == 0 || dotIndex == filename.length() - 1) {
            filename += ".dat";
        }
        
        return LocalDateTime.now().toLocalDate() + "_" + filename;
    }
}

class FileValidator {
    public boolean validateUrl(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        try {
            String lowercaseUrl = url.toLowerCase();
            if (lowercaseUrl.contains("..")) {
                return false;
            }
            
            // 表面安全检查但存在绕过可能
            return lowercaseUrl.endsWith(".png") || 
                   lowercaseUrl.endsWith(".jpg") ||
                   lowercaseUrl.endsWith(".jpeg") ||
                   lowercaseUrl.endsWith(".gif");
        } catch (Exception e) {
            return false;
        }
    }

    public boolean validateContent(byte[] content) {
        if (content == null || content.length < 8) {
            return false;
        }
        
        // 简单的文件头校验（示例）
        String header = bytesToHex(content, 0, 4);
        return header.startsWith("89504E47") || // PNG
               header.startsWith("FFD8FFD8");   // JPEG
    }
    
    private String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02X", bytes[offset + i] & 0xFF));
        }
        return sb.toString();
    }
}