package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.lang.reflect.Method;
import java.util.Map;

@SpringBootApplication
public class SsrfApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfApplication.class, args);
    }

    @RestController
    public static class VulnerableController {

        @PostMapping("/api/data")
        public ResponseEntity<String> fetchData(@RequestBody Map<String, String> payload) {
            try {
                // 使用元编程特性动态调用处理方法
                Class<?> handlerClass = Class.forName("com.example.ssrf.DataHandler");
                Object handlerInstance = handlerClass.getDeclaredConstructor().newInstance();
                
                Method method = handlerClass.getMethod("process", String.class);
                String result = (String) method.invoke(handlerInstance, payload.get("endpoint"));
                
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Internal Server Error");
            }
        }
    }

    public static class DataHandler {
        // 通过动态加载类实现的业务逻辑
        public String process(String endpoint) {
            try {
                // 漏洞核心点：直接拼接用户输入
                String targetUrl = "https://internal-api.example.com/data?source=" + endpoint;
                
                // 使用RestTemplate发起内部请求
                RestTemplate restTemplate = new RestTemplate();
                // 危险的URL访问（无任何验证）
                return restTemplate.getForObject(targetUrl, String.class);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}
// 编译运行后，攻击者可通过以下方式攻击：
// curl -X POST http://localhost:8080/api/data -H "Content-Type: application/json" 
// -d '{"endpoint": "file:///etc/passwd"}'