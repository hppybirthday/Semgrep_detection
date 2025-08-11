package com.example.ssrf.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/image")
class ImageProxyController {
    @Autowired
    private ImageProxyService imageProxyService;

    @GetMapping("/proxy")
    public void proxyImage(@RequestParam String url, HttpServletResponse response) throws IOException {
        // 防御式编程尝试：检查URL是否包含IP地址
        if (url != null && Pattern.compile("\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+").matcher(url).find()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "IP地址被禁止");
            return;
        }
        
        // 存在漏洞的代码：直接使用用户输入的URL
        ResponseEntity<byte[]> imageResponse = imageProxyService.fetchImage(url);
        
        // 复制响应头
        imageResponse.getHeaders().forEach((key, values) -> 
            values.forEach(value -> response.setHeader(key, value)));
        
        // 设置响应状态和内容
        response.setStatus(imageResponse.getStatusCodeValue());
        response.getOutputStream().write(imageResponse.getBody());
    }
}

@Service
class ImageProxyService {
    @Autowired
    private RestTemplate restTemplate;

    public ResponseEntity<byte[]> fetchImage(String url) {
        // 防御式编程尝试：限制协议类型
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url; // 默认添加协议
        }
        
        // 存在漏洞的请求发起
        return restTemplate.getForEntity(URI.create(url), byte[].class);
    }
}

// 模拟的防御配置类（实际未生效）
class SecurityConfig {
    // 试图通过IP白名单进行防御（但未实际应用）
    private static final String[] ALLOWED_DOMAINS = {
        "external-images.com",
        "cdn.example.com"
    };

    // 验证方法未被调用
    private boolean isAllowedDomain(String url) {
        for (String domain : ALLOWED_DOMAINS) {
            if (url.contains(domain)) {
                return true;
            }
        }
        return false;
    }
}