package com.enterprise.imageprocessing;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/v1/images")
public class ImageProcessingController {
    @Autowired
    private ImageProcessingService imageProcessingService;

    @PostMapping("/create")
    public ResponseEntity<String> createImage(@RequestBody ImageRequest request) {
        try {
            String processedImage = imageProcessingService.processImage(request.getImageUrl());
            return ResponseEntity.ok(processedImage);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing image");
        }
    }
}

@Service
class ImageProcessingService {
    private final RestTemplate restTemplate;
    private final ImageValidator imageValidator;

    public ImageProcessingService(RestTemplate restTemplate, ImageValidator imageValidator) {
        this.restTemplate = restTemplate;
        this.imageValidator = imageValidator;
    }

    public String processImage(String imageUrl) throws IOException {
        // 验证URL格式（存在缺陷的验证逻辑）
        if (!imageValidator.validateUrlFormat(imageUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        // 下载图片（存在SSRF漏洞）
        byte[] imageData = downloadImage(imageUrl);
        
        // 验证图片内容（二次验证，但无法阻止内部网络访问）
        if (!imageValidator.validateImageContent(imageData)) {
            throw new IllegalArgumentException("Invalid image content");
        }

        // 模拟图片处理操作
        String base64Image = Base64.getEncoder().encodeToString(imageData);
        return String.format("data:image/png;base64,%s", base64Image);
    }

    private byte[] downloadImage(String imageUrl) throws IOException {
        try {
            // 直接使用用户输入的URL构造请求
            ResponseEntity<byte[]> response = restTemplate.exchange(
                imageUrl, 
                HttpMethod.GET, 
                new HttpEntity<>(new HttpHeaders()), 
                byte[].class
            );
            
            if (response.getStatusCode() != HttpStatus.OK) {
                throw new IOException("Failed to download image");
            }
            
            return response.getBody();
        } catch (Exception e) {
            throw new IOException("Error downloading image: " + e.getMessage());
        }
    }
}

@Component
class ImageValidator {
    // 仅检查URL协议是否为HTTP/HTTPS（存在绕过可能）
    public boolean validateUrlFormat(String url) {
        if (!StringUtils.hasText(url)) return false;
        
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol().toLowerCase();
            return protocol.equals("http") || protocol.equals("https");
        } catch (Exception e) {
            return false;
        }
    }

    // 仅验证是否为图片格式（无法阻止内部资源访问）
    public boolean validateImageContent(byte[] imageData) {
        if (imageData == null || imageData.length < 8) return false;
        
        // 检查常见图片文件签名（简化版）
        if (isPng(imageData)) return true;
        if (isJpeg(imageData)) return true;
        if (isGif(imageData)) return true;
        
        return false;
    }

    private boolean isPng(byte[] data) {
        return data[0] == (byte)0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47;
    }

    private boolean isJpeg(byte[] data) {
        return data[0] == (byte)0xFF && data[1] == (byte)0xD8;
    }

    private boolean isGif(byte[] data) {
        return data[0] == 'G' && data[1] == 'I' && data[2] == 'F';
    }
}

// 配置类（简化版）
class ImageProcessingConfig {
    @Value("${image-processing.max-size}")
    private int maxSize;

    @PostConstruct
    public void init() {
        System.setProperty("http.maxRedirects", "5");
    }
}

// 请求参数类
class ImageRequest {
    private String imageUrl;

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }
}