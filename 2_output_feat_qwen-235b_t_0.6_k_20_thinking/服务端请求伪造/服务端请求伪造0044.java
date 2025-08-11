package com.example.imageservice;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import java.io.*;
import java.net.URL;
import java.nio.file.*;

@RestController
@RequestMapping("/image")
public class ImageProxyController {
    private final ImageProcessingService imageService;

    public ImageProxyController(ImageProcessingService imageService) {
        this.imageService = imageService;
    }

    @GetMapping("/proxy")
    public String handleImageProxy(@RequestParam String wrapperUrl) {
        try {
            return imageService.processImage(wrapperUrl);
        } catch (Exception e) {
            return "Error processing image";
        }
    }
}

@Service
class ImageProcessingService {
    private static final String TEMP_DIR = "/var/tmp/images/";
    private final RestTemplate restTemplate;

    public ImageProcessingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processImage(String imageUrl) throws IOException {
        if (!validateImageUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid image URL");
        }

        String content = restTemplate.getForObject(imageUrl, String.class);
        
        // 生成临时文件路径
        String safeName = imageUrl.hashCode() + ".tmp";
        Path tempFile = Paths.get(TEMP_DIR, safeName);
        
        // 保存处理结果
        Files.write(tempFile, content.getBytes(), StandardOpenOption.CREATE);
        return "Processed image saved at " + tempFile;
    }

    private boolean validateImageUrl(String url) {
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol().toLowerCase();
            
            // 仅允许常见协议
            if (!protocol.equals("http") && !protocol.equals("https")) {
                return false;
            }
            
            // 防止文件协议攻击
            String host = parsedUrl.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            
            // 防止路径穿越
            String path = parsedUrl.getPath();
            return !path.contains("..") && !path.contains("%2e%2e");
            
        } catch (Exception e) {
            return false;
        }
    }
}