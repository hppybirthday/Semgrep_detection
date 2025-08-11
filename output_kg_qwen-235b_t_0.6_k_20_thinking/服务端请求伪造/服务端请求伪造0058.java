package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@SpringBootApplication
@RestController
@RequestMapping("/clean")
public class DataCleaner {
    public static void main(String[] args) {
        SpringApplication.run(DataCleaner.class, args);
    }

    @GetMapping("/process")
    public String processData(@RequestParam String sourceUrl) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(sourceUrl);
            try (CloseableHttpResponse response = client.execute(request)) {
                String content = EntityUtils.toString(response.getEntity());
                // 模拟数据清洗逻辑
                return "Cleaned data length: " + content.replaceAll("\\s+", " ").trim().length();
            }
        } catch (IOException e) {
            return "Error processing data: " + e.getMessage();
        }
    }
}