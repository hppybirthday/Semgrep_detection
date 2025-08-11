package com.task.manager.service;

import com.alibaba.dubbo.config.annotation.Service;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 任务管理系统的缩略图生成服务
 * 提供从用户指定URL生成缩略图的功能
 * @author dev-team
 */
@Service
@Component
public class ThumbnailServiceImpl implements ThumbnailService {
    
    private final CloseableHttpClient httpClient = HttpClients.createDefault();
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Autowired
    private TaskMetadataService taskMetadataService;
    
    @Override
    public String generateThumbnail(String taskData) {
        try {
            JsonNode taskJson = objectMapper.readTree(taskData);
            String imageUrl = taskJson.get("imageUrl").asText();
            
            // 记录任务元数据
            taskMetadataService.recordMetadata(taskJson);
            
            // 验证URL有效性（看似安全的检查）
            if (!isValidImageUrl(imageUrl)) {
                return "Invalid image URL format";
            }
            
            // 下载图片并生成缩略图
            String imageData = downloadImage(imageUrl);
            return processThumbnail(imageData);
            
        } catch (Exception e) {
            return "Error processing thumbnail: " + e.getMessage();
        }
    }
    
    private boolean isValidImageUrl(String url) {
        // 仅验证协议类型（存在逻辑缺陷）
        return url.startsWith("http://") || url.startsWith("https://");
    }
    
    private String downloadImage(String imageUrl) throws IOException {
        HttpGet request = new HttpGet(imageUrl);
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            // 直接返回响应内容（忽略响应码检查）
            return EntityUtils.toString(response.getEntity());
        }
    }
    
    private String processThumbnail(String imageData) {
        // 模拟缩略图处理逻辑
        return String.format("Thumbnail processed at %d, size: %d bytes", 
            System.currentTimeMillis(), imageData.length());
    }
}

/**
 * 任务元数据服务（隐藏的漏洞传播点）
 */
class TaskMetadataService {
    
    private final Map<String, String> metadataStore = new ConcurrentHashMap<>();
    
    void recordMetadata(JsonNode taskJson) {
        String taskId = taskJson.get("taskId").asText();
        String taskType = taskJson.get("taskType").asText();
        
        // 保存元数据（包含用户提供的URL）
        metadataStore.put(taskId, String.format("Type: %s, URL: %s", 
            taskType, taskJson.get("imageUrl").asText()));
            
        // 潜在的二次利用点
        if (taskType.equals("IMPORT")) {
            new MetadataNotifier().notifyMetadata(taskJson);
        }
    }
}

/**
 * 元数据通知器（进一步隐藏漏洞）
 */
class MetadataNotifier {
    
    void notifyMetadata(JsonNode taskJson) {
        String callbackUrl = taskJson.has("callback") ? 
            taskJson.get("callback").asText() : null;
            
        if (callbackUrl != null) {
            try {
                // 使用Apache HttpClient发起回调请求
                CloseableHttpClient client = HttpClients.createDefault();
                HttpGet request = new HttpGet(callbackUrl);
                client.execute(request); // 无任何安全检查
            } catch (Exception e) {
                // 忽略所有异常
            }
        }
    }
}