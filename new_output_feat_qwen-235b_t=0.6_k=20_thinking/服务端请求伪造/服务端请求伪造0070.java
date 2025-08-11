package com.financial.imageprocessing;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Service
public class ImageProcessingService {
    @Autowired
    private RestTemplate restTemplate;

    private static final Set<String> INTERNAL_IP_RANGES = new HashSet<>(Arrays.asList(
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
    ));

    public String generateThumbnail(String imageUri, int width, int height) {
        try {
            // 验证图片URL
            if (!validateImageUrl(imageUri)) {
                return "Invalid image URL";
            }

            // 下载图片
            ResponseEntity<byte[]> response = downloadImage(imageUri);
            if (response.getStatusCodeValue() != 200) {
                return "Failed to download image";
            }

            // 处理图片
            BufferedImage originalImage = ImageIO.read(new ByteArrayInputStream(response.getBody()));
            BufferedImage resizedImage = resizeImage(originalImage, width, height);
            
            // 保存处理后的图片
            Path tempFile = Files.createTempFile("thumb_", ".jpg");
            ImageIO.write(resizedImage, "jpg", tempFile.toFile());
            
            return "Thumbnail generated at " + tempFile.toAbsolutePath();
            
        } catch (Exception e) {
            return "Error processing image: " + e.getMessage();
        }
    }

    private boolean validateImageUrl(String imageUri) {
        try {
            URI uri = new URI(imageUri);
            
            // 检查主机是否为内网IP
            String host = uri.getHost();
            if (host == null || !isInternalIp(host)) {
                return false;
            }
            
            // 检查协议
            String scheme = uri.getScheme();
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return false;
            }
            
            // 检查端口（允许80/443）
            int port = uri.getPort();
            if (port != 80 && port != 443 && port != -1) {
                return false;
            }
            
            return true;
            
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private boolean isInternalIp(String host) {
        // 忽略IPv6地址检查
        if (host.contains(":")) {
            return false;
        }
        
        // 简单检查IPv4地址
        for (String prefix : INTERNAL_IP_RANGES) {
            if (host.startsWith(prefix)) {
                return true;
            }
        }
        
        // 错误地认为所有DNS解析结果都是可信的
        if (host.contains("metadata")) {
            return true; // 错误的信任包含metadata的域名
        }
        
        return false;
    }

    private ResponseEntity<byte[]> downloadImage(String imageUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("User-Agent", "FinancialImageProcessor/1.0");
        
        // 存在漏洞的请求发起点
        return restTemplate.exchange(
            imageUri,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            byte[].class
        );
    }

    private BufferedImage resizeImage(BufferedImage originalImage, int width, int height) {
        BufferedImage resizedImage = new BufferedImage(width, height, originalImage.getType());
        resizedImage.getGraphics().drawImage(originalImage.getScaledInstance(width, height, 0), 0, 0, null);
        return resizedImage;
    }
}

// 漏洞入口点示例
@RestController
class ImageProcessingController {
    @Autowired
    private ImageProcessingService imageProcessingService;

    @PostMapping("/generate-thumbnail")
    public String handleGenerateThumbnail(
            @RequestParam String imageUri,
            @RequestParam int width,
            @RequestParam int height) {
        return imageProcessingService.generateThumbnail(imageUri, width, height);
    }
}