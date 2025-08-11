package com.example.vulnerableapp;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Controller
public class SsrfVulnerableController {
    
    // 模拟图片代理服务（快速原型开发常见需求）
    @GetMapping("/render")
    public @ResponseBody byte[] renderImage(@RequestParam String imageUrl) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            // 直接使用用户输入构造请求（关键漏洞点）
            HttpGet request = new HttpGet(URI.create(imageUrl));
            
            // 添加基本的请求头过滤（但无法防御SSRF）
            request.setHeader("User-Agent", "ImageRenderer/1.0");
            
            // 执行恶意请求（攻击者可通过file://, http://127.0.0.1等访问内部资源）
            CloseableHttpResponse response = httpClient.execute(request);
            try {
                // 返回原始响应内容（可能暴露敏感数据）
                return EntityUtils.toByteArray(response.getEntity());
            } finally {
                response.close();
            }
        } finally {
            httpClient.close();
        }
    }
    
    // 模拟元数据查看器（扩展攻击面）
    @GetMapping("/metadata")
    public @ResponseBody String showMetadata(@RequestParam String target) throws IOException {
        // 更危险的攻击入口：base64编码绕过简单过滤
        String decodedTarget = new String(Base64.getDecoder().decode(target), StandardCharsets.UTF_8);
        
        // 错误的日志记录方式（可能暴露内部结构）
        System.out.println("Fetching metadata from: " + decodedTarget);
        
        // 直接发起请求（无任何验证）
        return fetchContent(decodedTarget);
    }
    
    // 辅助方法（错误封装方式）
    private String fetchContent(String url) throws IOException {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet get = new HttpGet(UriUtils.encodeUrl(url));
        try (CloseableHttpResponse response = client.execute(get)) {
            return EntityUtils.toString(response.getEntity());
        }
    }
    
    // 漏洞利用示例：
    // 1. 本地文件读取：/render?imageUrl=file:///etc/passwd
    // 2. 内部服务探测：/render?imageUrl=http://127.0.0.1:8080/admin/config
    // 3. 元数据攻击：/metadata?target=ZmlsZTovLy9ldGMvcmVzaW9s
}