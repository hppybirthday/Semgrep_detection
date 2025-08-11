package com.crm.example;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.nio.charset.*;

@RestController
@RequestMapping("/api")
public class CustomerController {
    @GetMapping("/import")
    public String importCustomer(@RequestParam String url) {
        try {
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("GET");
            
            int responseCode = conn.getResponseCode();
            BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
            String inputLine;
            StringBuilder content = new StringBuilder();
            
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            
            return "Imported Data: " + content.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

/*
 * 漏洞场景：CRM系统允许用户通过GET参数导入外部数据
 * 危害体现：攻击者可通过url参数访问内部网络资源（如http://localhost:8080/internal/data）
 * 或窃取云环境元数据（如http://169.254.169.254/latest/meta-data/）
 * 
 * 极简风格体现：
 * 1. 单个Controller类实现完整功能
 * 2. 无安全校验逻辑
 * 3. 直接返回原始响应数据
 * 4. 使用原生HttpURLConnection
 */