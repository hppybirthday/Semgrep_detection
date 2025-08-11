package com.example.ssrf.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class SsrfVulnerableApplication {

    private final RestTemplate restTemplate = new RestTemplate();

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApplication.class, args);
    }

    @GetMapping("/fetch")
    public String fetchData(@RequestParam String url) {
        try {
            // 漏洞点：直接使用用户输入的URL进行服务器端请求
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(url), String.class);
            return "Response: " + response.getBody();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟企业级后端常见的元编程场景
    @GetMapping("/process/{handler}")
    public String processRequest(@PathVariable String handler, @RequestParam Map<String, String> params) {
        try {
            // 漏洞点：动态处理逻辑中拼接URL
            String baseUrl = getHandlerBaseUrl(handler);
            String targetUrl = buildTargetUrl(baseUrl, params);
            
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(targetUrl), String.class);
            return "Processed: " + response.getBody();
        } catch (Exception e) {
            return "Processing Error: " + e.getMessage();
        }
    }

    // 模拟元编程中的动态URL构建
    private String getHandlerBaseUrl(String handler) {
        Map<String, String> handlerMap = new HashMap<>();
        handlerMap.put("image", "http://internal-image-service/");
        handlerMap.put("data", "http://internal-data-api/");
        return handlerMap.getOrDefault(handler, "http://default-internal-service/");
    }

    // 漏洞点：不安全的URL拼接
    private String buildTargetUrl(String baseUrl, Map<String, String> params) {
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        urlBuilder.append("?");
        
        for (Map.Entry<String, String> entry : params.entrySet()) {
            urlBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        
        if (urlBuilder.charAt(urlBuilder.length() - 1) == '&') {
            urlBuilder.deleteCharAt(urlBuilder.length() - 1);
        }
        
        return urlBuilder.toString();
    }

    // 模拟企业级服务中的健康检查端点（存在漏洞）
    @GetMapping("/healthcheck")
    public String checkServiceHealth(@RequestParam String serviceUrl) {
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(serviceUrl), String.class);
            return "Service Health: " + response.getBody();
        } catch (Exception e) {
            return "Healthcheck Failed: " + e.getMessage();
        }
    }
}