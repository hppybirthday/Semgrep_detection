package com.example.crawler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.HashMap;

@RestController
@RequestMapping("/api/crawler")
public class CrawlerController {
    private final CrawlerService crawlerService = new CrawlerService();

    @PostMapping("/submit")
    public String submitTask(@RequestParam String classData) {
        try {
            crawlerService.processTask(classData);
            return "Task processed successfully";
        } catch (Exception e) {
            return "Error processing task: " + e.getMessage();
        }
    }
}

class CrawlerService {
    private final ObjectMapper mapper;

    public CrawlerService() {
        mapper = new ObjectMapper();
        // 不安全的配置：启用默认类型处理
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
    }

    public void processTask(String jsonData) throws JsonProcessingException {
        // 漏洞点：直接反序列化不可信数据
        CrawlerTask task = mapper.readValue(jsonData, CrawlerTask.class);
        task.execute();
    }
}

class CrawlerTask implements Serializable {
    private String url;
    private HashMap<String, Object> metadata;

    public CrawlerTask() {
        metadata = new HashMap<>();
    }

    public void execute() {
        System.out.println("Crawling URL: " + url);
        // 模拟爬虫行为
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            System.out.println("Metadata - " + entry.getKey() + ": " + entry.getValue());
        }
    }

    // Getters and setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public HashMap<String, Object> getMetadata() { return metadata; }
    public void setMetadata(HashMap<String, Object> metadata) { this.metadata = metadata; }
}