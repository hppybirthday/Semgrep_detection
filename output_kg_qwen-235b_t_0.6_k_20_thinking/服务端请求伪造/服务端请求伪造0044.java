package com.crm.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/leads")
public class LeadController {
    @Autowired
    private RestTemplate restTemplate;

    // 模拟CRM系统中的潜在漏洞接口：外部数据导入
    @PostMapping("/import")
    public ResponseEntity<String> importLeads(@RequestParam String dataSourceUrl) {
        try {
            // 危险操作：直接使用用户输入的URL发起请求
            String response = restTemplate.getForObject(dataSourceUrl, String.class);
            
            // 模拟处理响应数据（实际可能解析CSV/JSON并存储）
            Map<String, Object> result = new HashMap<>();
            result.put("status", "success");
            result.put("data", response.substring(0, Math.min(100, response.length())));
            return ResponseEntity.ok(result.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\\"status\\":\\"error\\",\\"message\\":\\"" + e.getMessage() + "\\"}");
        }
    }

    // 模拟防御式编程中的无效校验（存在绕过可能）
    private boolean isValidUrl(String url) {
        // 仅检查协议类型，无法阻止内部网络访问
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }
}

// 配置类（简化版）
package com.crm.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

// 启动类（简化版）
package com.crm.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}