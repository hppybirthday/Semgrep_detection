package com.example.vulnerableapp;

import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/clean")
public class DataCleanerController {
    
    public static void main(String[] args) {
        SpringApplication.run(DataCleanerController.class, args);
    }

    @PostMapping(path = "/csv", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public String cleanCSV(@RequestParam("file") byte[] fileContent) throws IOException {
        // 模拟CSV数据清洗流程
        InputStream csvStream = new ByteArrayInputStream(fileContent);
        List<String> lines = Arrays.asList(IOUtils.readLines(csvStream, StandardCharsets.UTF_8));
        
        // 假设CSV格式：id,url
        StringBuilder cleanedData = new StringBuilder();
        for (String line : lines) {
            String[] parts = line.split(",");
            if (parts.length == 2) {
                String id = parts[0];
                String targetUrl = parts[1];
                
                // 漏洞点：直接使用用户输入的URL发起请求
                String response = fetchRemoteContent(targetUrl);
                
                // 简单清洗操作（移除HTML标签）
                String cleaned = response.replaceAll("<[^>]*>", "");
                cleanedData.append(id).append(",").append(cleaned).append("\
");
            }
        }
        
        return cleanedData.toString();
    }

    private String fetchRemoteContent(String urlString) throws IOException {
        // 模拟远程数据抓取
        URL url = new URL(urlString);
        try (InputStream in = url.openStream()) {
            return IOUtils.toString(in, StandardCharsets.UTF_8);
        }
    }
}