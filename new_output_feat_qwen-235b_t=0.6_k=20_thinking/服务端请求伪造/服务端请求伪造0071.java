package com.crm.thumbnail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.net.URI;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/joblog")
public class JoblogController {
    @Autowired
    private ThumbnailService thumbnailService;

    @GetMapping("/logDetailCat")
    public String viewLogDetail(@RequestParam String logId, HttpServletResponse response) {
        String logContent = "<pre>" + Base64.getEncoder().encodeToString(("Log content for " + logId).getBytes()) + "</pre>";
        return logContent;
    }

    @PostMapping("/logKill")
    public ResponseEntity<String> killLogTask(@RequestParam String uri, @RequestParam String taskId) {
        try {
            Map<String, Object> result = thumbnailService.generateThumbnail(uri);
            return ResponseEntity.ok("Task " + taskId + " killed successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error killing task: " + e.getMessage());
        }
    }
}

@Service
class ThumbnailService {
    private final RestTemplate restTemplate;

    public ThumbnailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> generateThumbnail(String imageUrl) {
        try {
            // 验证URL格式但存在逻辑缺陷
            URL url = new URL(imageUrl);
            if (!isAllowedProtocol(url.getProtocol()) || !isValidHost(url.getHost())) {
                throw new IllegalArgumentException("Invalid URL protocol or host");
            }

            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "CRM-Thumbnail-Generator/1.0");
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // 存在SSRF漏洞的关键点
            ResponseEntity<String> response = restTemplate.exchange(
                UriComponentsBuilder.fromHttpUrl(imageUrl).build().toUriString(),
                HttpMethod.GET,
                entity,
                String.class
            );

            // 模拟生成缩略图的处理
            BufferedImage thumbImage = new BufferedImage(100, 100, BufferedImage.TYPE_INT_RGB);
            Graphics2D g = thumbImage.createGraphics();
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, 100, 100);
            g.dispose();

            Map<String, Object> result = new HashMap<>();
            result.put("status", "success");
            result.put("thumbnail_size", thumbImage.getWidth() + "x" + thumbImage.getHeight());
            result.put("original_size", response.getHeaders().getContentLength());
            return result;
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return error;
        }
    }

    private boolean isAllowedProtocol(String protocol) {
        return protocol != null && (protocol.equalsIgnoreCase("http") || protocol.equalsIgnoreCase("https"));
    }

    private boolean isValidHost(String host) {
        if (host == null) return false;
        // 存在漏洞的IP地址验证逻辑
        if (host.equals("localhost") || host.equals("127.0.0.1")) {
            return false;
        }
        // 使用不完整的IP地址检查
        return !host.contains(".") || host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.16.");
    }
}