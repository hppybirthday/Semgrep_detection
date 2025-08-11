package com.enterprise.logservice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Base64;

@Service
public class LogProcessingService {
    
    private final LogService logService;
    private final RestTemplate restTemplate;
    private final StorageService storageService;
    
    @Autowired
    public LogProcessingService(LogService logService, 
                              RestTemplate restTemplate,
                              StorageService storageService) {
        this.logService = logService;
        this.restTemplate = restTemplate;
        this.storageService = storageService;
    }

    /**
     * 处理日志中的图片资源
     * @param logId 日志记录ID
     */
    public void processLogImage(String logId) {
        // 获取原始日志数据
        String logData = logService.getLogDetails(logId);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode logJson = mapper.readTree(logData);
            
            // 提取日志中的URI字段
            String uri = logJson.get("image").asText();
            
            // 构建完整URL
            String imageUrl = UriComponentsBuilder.fromHttpUrl("https://logs.example.com/media")
                .pathSegment(uri)
                .build()
                .toUriString();

            // 下载图片内容
            byte[] imageData = fetchImageContent(imageUrl);
            
            // 上传至企业存储系统
            if (imageData.length > 0) {
                storageService.uploadImage(imageData, "processed/" + uri);
            }
            
        } catch (IOException | NullPointerException e) {
            // 忽略下载失败情况
        }
    }
    
    private byte[] fetchImageContent(String imageUrl) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + generateInternalToken());
        
        HttpEntity<byte[]> response = restTemplate.exchange(
            imageUrl, 
            org.springframework.http.HttpMethod.GET, 
            new HttpEntity<>(headers), 
            byte[].class
        );
        
        return response.getBody();
    }
    
    private String generateInternalToken() {
        // 模拟生成内部访问令牌
        return Base64.getEncoder().encodeToString("internal:secret".getBytes());
    }
}

// 模拟依赖接口
class LogService {
    public String getLogDetails(String logId) {
        // 模拟从数据库获取日志数据
        // 实际可能包含用户可控的URI字段
        return String.format("{\\"id\\":\\"%s\\",\\"image\\":\\"%s\\"}", logId, "image.jpg");
    }
}

class StorageService {
    public void uploadImage(byte[] data, String path) {
        // 模拟上传到企业存储系统
    }
}