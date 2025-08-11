package com.example.ml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

@SpringBootApplication
public class MLServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(MLServiceApplication.class, args);
    }
}

@RestController
class PredictionController {
    @GetMapping("/predict")
    public String predict(@RequestParam String dataUrl) {
        try {
            // 模拟加载远程数据进行预测
            URL url = new URL(dataUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 读取响应
            Scanner scanner = new Scanner(conn.getInputStream());
            StringBuilder response = new StringBuilder();
            while (scanner.hasNext()) {
                response.append(scanner.nextLine());
            }
            scanner.close();

            // 模拟模型处理
            return "Prediction result: " + processModelResponse(response.toString());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String processModelResponse(String response) {
        // 简单模拟模型处理逻辑
        return response.hashCode() % 2 == 0 ? "ClassA" : "ClassB";
    }
}

// 漏洞点：直接使用用户提供的URL进行外部请求，没有进行任何安全校验
// 攻击者可以构造如：file:///etc/passwd 或 http://internal-db:5432/ 的请求
// 该漏洞允许攻击者探测内网服务或读取服务器本地文件