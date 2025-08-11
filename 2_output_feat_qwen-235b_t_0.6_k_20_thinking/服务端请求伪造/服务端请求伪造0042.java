package com.task.manager.importer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

@Service
public class TaskImporter {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public TaskImporter(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public ImportResult importTaskFromUrl(ImportRequest request) {
        try {
            // 验证URL格式
            URI uri = validateUrlFormat(request.getUrl());
            
            // 获取并验证域名
            String domain = extractDomain(uri.getHost());
            
            // 构造请求头
            HttpHeaders headers = buildHeaders(request);
            
            // 获取远程数据
            ResponseEntity<String> response = fetchRemoteData(uri, headers);
            
            // 解析任务数据
            return parseTaskData(response.getBody());
            
        } catch (Exception e) {
            return new ImportResult().setError("导入失败: " + e.getMessage());
        }
    }

    private URI validateUrlFormat(String url) throws URISyntaxException {
        // 简单验证URL格式
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException("URL必须使用HTTP/HTTPS协议");
        }
        return new URI(url);
    }

    private String extractDomain(String host) {
        // 简单域名提取
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("无效的主机名");
        }
        return host;
    }

    private HttpHeaders buildHeaders(ImportRequest request) {
        HttpHeaders headers = new HttpHeaders();
        if (request.getAuthToken() != null) {
            headers.setBearerAuth(request.getAuthToken());
        }
        headers.set("User-Agent", "TaskManager/1.0");
        return headers;
    }

    private ResponseEntity<String> fetchRemoteData(URI uri, HttpHeaders headers) {
        // 发起远程请求
        return restTemplate.exchange(
            uri,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            String.class
        );
    }

    private ImportResult parseTaskData(String jsonData) throws IOException {
        // 解析JSON数据
        JsonNode rootNode = objectMapper.readTree(jsonData);
        // 处理任务数据逻辑
        return new ImportResult()
            .setSuccessCount(rootNode.size())
            .setTotalCount(rootNode.size());
    }

    // 请求参数类
    public static class ImportRequest {
        private String url;
        private String authToken;
        
        // Getters and Setters
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        
        public String getAuthToken() { return authToken; }
        public void setAuthToken(String authToken) { this.authToken = authToken; }
    }

    // 导入结果类
    public static class ImportResult {
        private int successCount;
        private int totalCount;
        private String error;
        
        // Getters and Setters
        public int getSuccessCount() { return successCount; }
        public void setSuccessCount(int successCount) { this.successCount = successCount; }
        
        public int getTotalCount() { return totalCount; }
        public void setTotalCount(int totalCount) { this.totalCount = totalCount; }
        
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }
}