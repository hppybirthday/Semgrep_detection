package com.example.ssrf.demo;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;

@Controller
public class DataCleanerController {

    @GetMapping("/clean")
    @ResponseBody
    public String cleanData(@RequestParam("url") String url) {
        try {
            // 模拟数据清洗流程：从远程URL获取数据并处理
            String rawData = fetchRemoteData(url);
            String cleanedData = sanitizeData(rawData);
            return "清洗完成: " + cleanedData.substring(0, Math.min(100, cleanedData.length())) + "...";
        } catch (Exception e) {
            return "数据清洗失败: " + e.getMessage();
        }
    }

    private String fetchRemoteData(String url) throws IOException {
        // 危险操作：直接使用用户输入的URL发起请求
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                return EntityUtils.toString(entity);
            }
        }
        
        return "";
    }

    private String sanitizeData(String data) {
        // 简单的HTML标签清理示例
        return data.replaceAll("<[^>]*>", "").trim();
    }

    // 模拟应用入口
    public static void main(String[] args) {
        // Spring Boot应用启动代码（实际应通过Spring Boot启动）
        System.out.println("数据清洗服务启动中...");
        // 访问示例：http://localhost:8080/clean?url=http://example.com/data
    }
}