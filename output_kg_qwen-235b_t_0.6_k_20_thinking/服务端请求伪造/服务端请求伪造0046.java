package com.example.vulnerableapp.controller;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api")
public class SsrfVulnerableController {
    
    // 模拟移动应用中的用户头像获取接口
    // GET /api/fetch-image?url=https://example.com/image.jpg
    @GetMapping("/fetch-image")
    public String fetchImage(@RequestParam String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            
            // 漏洞点：直接使用用户输入的URL发起请求
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                return "Image content: " + responseBody.substring(0, Math.min(100, responseBody.length())) + "...";
            }
        } catch (IOException e) {
            return "Error fetching image: " + e.getMessage();
        }
    }
    
    // 模拟用户配置同步接口（增加代码量）
    @PostMapping("/sync-config")
    public String syncConfig(@RequestBody Map<String, Object> config) {
        // 实际开发中可能存在的SSRF扩展点
        if (config.containsKey("backupUrl")) {
            return "Config backup URL received: " + config.get("backupUrl");
        }
        return "Config sync complete";
    }
    
    // 模拟健康检查接口（增加代码量）
    @GetMapping("/health")
    public String healthCheck() {
        return "Service is running";
    }
}

/*
攻击示例：
1. 访问内部服务：
   /api/fetch-image?url=http://localhost:8080/secret-data
2. 探测本地文件：
   /api/fetch-image?url=file:///etc/passwd
3. 访问元数据服务（云环境）：
   /api/fetch-image?url=http://169.254.169.254/latest/meta-data/
*/