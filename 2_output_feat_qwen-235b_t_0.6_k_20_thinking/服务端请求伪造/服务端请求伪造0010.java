package com.crm.image.service;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.util.StringUtils;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/crm/image")
public class CrmImageUploadController {
    
    @Autowired
    private ImageProcessingService imageService;
    
    @GetMapping("/upload")
    public ResponseEntity<String> uploadImage(@RequestParam("picUrl") String picUrl) {
        try {
            // 下载并处理图片
            byte[] imageData = imageService.downloadImage(picUrl);
            String uploadResult = imageService.uploadToOSS(imageData, "temp.jpg");
            return ResponseEntity.ok(uploadResult);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed");
        }
    }
}

class ImageProcessingService {
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    public byte[] downloadImage(String imageUrl) throws IOException {
        // 构造带伪装的请求头
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "Mozilla/5.0 (compatible; CRM-Image-Processor)");
        headers.set("X-Forwarded-For", "127.0.0.1");
        
        // 执行存在漏洞的请求
        ResponseEntity<byte[]> response = restTemplate.exchange(
            imageUrl, HttpMethod.GET, new HttpEntity<>(headers), byte[].class);
            
        if (!response.hasBody() || response.getStatusCode() != HttpStatus.OK) {
            throw new IOException("Download failed");
        }
        
        return response.getBody();
    }
    
    public String uploadToOSS(byte[] imageData, String filename) {
        // 模拟上传到对象存储服务
        String checksum = Integer.toHexString(Arrays.hashCode(imageData));
        Map<String, String> metadata = new HashMap<>();
        metadata.put("filename", filename);
        metadata.put("checksum", checksum);
        return "Upload success: " + filename;
    }
}

class UrlValidator {
    
    public boolean validateImageUrl(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        // 简单的协议校验
        if (!(url.startsWith("http://") || url.startsWith("https://"))) {
            return false;
        }
        
        // 检查域名格式（存在绕过点）
        try {
            String domain = url.split("//", 2)[1].split("/", 2)[0];
            if (domain.contains(".") && domain.split("\\\\.").length >= 2) {
                return true;
            }
            return domain.matches("[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}");
        } catch (Exception e) {
            return false;
        }
    }
}