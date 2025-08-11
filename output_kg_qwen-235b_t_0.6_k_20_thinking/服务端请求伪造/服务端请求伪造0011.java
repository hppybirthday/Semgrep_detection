package com.example.bank.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

@SpringBootApplication
public class SsrfVulnerableBankApp {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableBankApp.class, args);
    }
}

@RestController
@RequestMapping("/api/transfer")
class TransferController {
    private final RestTemplate restTemplate;

    public TransferController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping
    public String handleTransfer(@RequestParam String targetUrl, HttpServletResponse response) throws IOException {
        try {
            // 模拟银行转账预验证流程
            // Vulnerable point: 直接使用用户输入构造请求
            URI validationUri = new URI(targetUrl + "?amount=1000000");
            
            // 声明式编程风格：使用模板进行HTTP调用
            String validationResponse = restTemplate.getForObject(validationUri, String.class);
            
            if (validationResponse.contains("SUCCESS")) {
                // 实际转账逻辑应在此处执行
                return "Transfer validated successfully";
            }
            return "Transfer validation failed";
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Transfer error: " + e.getMessage());
            return null;
        }
    }
}

/*
攻击示例：
恶意用户可构造请求：
/api/transfer?targetUrl=http://internal-banking-api:8080/internal/transfer?account=attacker
导致服务器发起内部请求，绕过安全控制
*/