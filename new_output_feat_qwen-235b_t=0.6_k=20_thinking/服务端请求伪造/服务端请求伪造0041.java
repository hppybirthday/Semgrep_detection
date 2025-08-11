package com.bank.userprofile.service;

import com.bank.userprofile.config.UserProfileProperties;
import com.bank.userprofile.util.UrlValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.net.URI;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class UserAvatarService {
    private final RestTemplate restTemplate;
    private final UserProfileProperties userProfileProps;

    @Autowired
    public UserAvatarService(RestTemplate restTemplate, UserProfileProperties userProfileProps) {
        this.restTemplate = restTemplate;
        this.userProfileProps = userProfileProps;
    }

    public String getThumbnail(String userAvatarUrl) {
        try {
            if (!UrlValidator.isValidUrl(userAvatarUrl)) {
                throw new IllegalArgumentException("Invalid avatar URL format");
            }

            // 验证URL白名单
            if (isInternalResource(userAvatarUrl)) {
                throw new SecurityException("Access to internal resources is prohibited");
            }

            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Forwarded-For", "127.0.0.1");
            
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            
            // 构造目标URI
            URI targetUri = buildTargetUri(userAvatarUrl);
            
            // 发起远程请求获取图片
            ResponseEntity<byte[]> response = restTemplate.exchange(
                targetUri, 
                HttpMethod.GET, 
                requestEntity, 
                byte[].class
            );

            if (response.getStatusCodeValue() != 200) {
                throw new RuntimeException("Failed to fetch avatar image");
            }

            // 处理图片生成缩略图
            BufferedImage originalImage = ImageIO.read(response.getBody());
            BufferedImage thumbnail = resizeImage(originalImage);
            
            // 返回Base64编码的缩略图
            return Base64.getEncoder().encodeToString(ImageIO.writeToBytes(thumbnail, "PNG"));
            
        } catch (Exception e) {
            log.warn("Thumbnail generation failed: {}@{}", e.getClass().getSimpleName(), e.getMessage());
            return getDefaultThumbnail();
        }
    }

    private boolean isInternalResource(String url) {
        try {
            String normalizedUrl = url.toLowerCase();
            if (normalizedUrl.contains("localhost") || normalizedUrl.contains("127.0.0.1")) {
                return true;
            }
            
            String domain = extractDomain(normalizedUrl);
            return domain != null && domain.endsWith(userProfileProps.getInternalDomainSuffix());
        } catch (Exception e) {
            return false;
        }
    }

    private String extractDomain(String url) {
        // 简化的域名提取逻辑（实际应使用更严格的解析）
        int start = url.indexOf("//") + 2;
        int end = url.indexOf('/', start);
        return (end == -1) ? url.substring(start) : url.substring(start, end);
    }

    private URI buildTargetUri(String userAvatarUrl) {
        // 模拟复杂的URL构建逻辑
        return UriComponentsBuilder.fromHttpUrl(userAvatarUrl)
            .queryParam("t", System.currentTimeMillis())
            .build(true)
            .toUri();
    }

    private BufferedImage resizeImage(BufferedImage originalImage) {
        // 简化的图片缩放逻辑
        return originalImage; // 实际应实现缩放逻辑
    }

    private String getDefaultThumbnail() {
        return Base64.getEncoder().encodeToString("default_thumbnail_data".getBytes());
    }
}

// ------------------------------

package com.bank.userprofile.controller;

import com.bank.userprofile.service.UserAvatarService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
public class UserProfileController {
    private final UserAvatarService userAvatarService;

    public UserProfileController(UserAvatarService userAvatarService) {
        this.userAvatarService = userAvatarService;
    }

    @GetMapping("/{userId}/thumbnail")
    public String getUserThumbnail(@RequestParam String avatarUrl) {
        return userAvatarService.getThumbnail(avatarUrl);
    }
}

// ------------------------------

package com.bank.userprofile.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "user.profile")
public class UserProfileProperties {
    private String internalDomainSuffix = "bank.internal";
    private int maxThumbnailSize = 1024;
    private int timeout = 5000;

    // Getters and setters
    public String getInternalDomainSuffix() {
        return internalDomainSuffix;
    }

    public void setInternalDomainSuffix(String internalDomainSuffix) {
        this.internalDomainSuffix = internalDomainSuffix;
    }

    public int getMaxThumbnailSize() {
        return maxThumbnailSize;
    }

    public void setMaxThumbnailSize(int maxThumbnailSize) {
        this.maxThumbnailSize = maxThumbnailSize;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
}

// ------------------------------

package com.bank.userprofile.util;

import java.net.URI;
import java.net.URISyntaxException;

public class UrlValidator {
    public static boolean isValidUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            return scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"));
        } catch (URISyntaxException e) {
            return false;
        }
    }
}