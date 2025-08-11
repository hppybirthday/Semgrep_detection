package com.example.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class DataProcessingApplication {
    public static void main(String[] args) {
        SpringApplication.run(DataProcessingApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
class DataController {
    private final RestTemplate restTemplate;

    public DataController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/process")
    public Map<String, Object> processData(@RequestParam String dataSourceUrl) {
        // 模拟大数据处理流程
        String rawData = restTemplate.getForObject(dataSourceUrl, String.class);
        
        // 漏洞点：直接使用用户输入的URL参数
        if (rawData == null || rawData.isEmpty()) {
            throw new IllegalArgumentException("Invalid data source");
        }

        // 模拟数据清洗和处理
        Map<String, Integer> wordCount = new HashMap<>();
        Stream.of(rawData.split("\\\\s+"))
            .map(word -> word.replaceAll("[^a-zA-Z0-9]", ""))
            .filter(word -> !word.isEmpty())
            .forEach(word -> wordCount.put(word, 
                wordCount.getOrDefault(word, 0) + 1));

        // 生成处理结果
        Map<String, Object> result = new HashMap<>();
        result.put("total_words", wordCount.size());
        result.put("word_frequencies", wordCount.entrySet()
            .stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .collect(Collectors.toList()));
        
        return result;
    }
}