package com.cloudnative.gateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

/**
 * 内部资源访问服务，用于处理多租户环境下的文件代理下载请求
 */
@Service
public class InternalResourceService {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private static final String[] ALLOWED_SCHEMES = {"http", "https"};
    private static final int MAX_REDIRECTS = 3;

    @Autowired
    public InternalResourceService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * 处理文件代理下载请求
     * @param requestJson 请求参数JSON字符串
     * @return 文件元数据信息
     * @throws Exception 解析或下载异常
     */
    public ResourceMetadata handleFileDownload(String requestJson) throws Exception {
        Map<String, Object> params = parseRequestParams(requestJson);
        String targetUrl = constructTargetUrl(params);
        
        if (!isValidScheme(targetUrl)) {
            throw new IllegalArgumentException("Unsupported URL scheme");
        }

        return downloadAndStoreFile(targetUrl);
    }

    private Map<String, Object> parseRequestParams(String json) throws IOException {
        // 解析包含租户信息和文件路径的请求参数
        Map<String, Object> rawParams = objectMapper.readValue(json, HashMap.class);
        Map<String, Object> result = new HashMap<>();
        
        if (rawParams.containsKey("b") && rawParams.get("b") instanceof Object[]) {
            Object[] dataArray = (Object[]) rawParams.get("b");
            if (dataArray.length > 2 && dataArray[2] instanceof String) {
                result.put("pathSegment", dataArray[2]);
            }
        }
        
        if (rawParams.containsKey("p") && rawParams.get("p") instanceof Object[]) {
            Object[] paramArray = (Object[]) rawParams.get("p");
            if (paramArray.length > 2 && paramArray[2] instanceof String) {
                result.put("queryParams", paramArray[2]);
            }
        }
        
        return result;
    }

    private String constructTargetUrl(Map<String, Object> params) {
        StringBuilder urlBuilder = new StringBuilder("https://internal-api/");
        
        if (params.containsKey("pathSegment")) {
            urlBuilder.append(params.get("pathSegment"));
        }
        
        urlBuilder.append("?token=svc_account");
        
        if (params.containsKey("queryParams")) {
            urlBuilder.append("&").append(params.get("queryParams"));
        }
        
        return urlBuilder.toString();
    }

    private boolean isValidScheme(String url) {
        // 简单验证URL协议类型
        for (String scheme : ALLOWED_SCHEMES) {
            if (url.startsWith(scheme + "://")) {
                return true;
            }
        }
        return false;
    }

    private ResourceMetadata downloadAndStoreFile(String fileUrl) throws IOException {
        ResponseEntity<InputStreamResource> response = restTemplate.getForEntity(
            fileUrl, InputStreamResource.class);

        Path tempFile = Files.createTempFile("download_", ".tmp");
        Files.copy(response.getBody().getInputStream(), tempFile, StandardCopyOption.REPLACE_EXISTING);

        return new ResourceMetadata()
            .setFileId(tempFile.getFileName().toString())
            .setFileSize(Files.size(tempFile))
            .setDownloadUrl(fileUrl);
    }

    /**
     * 文件元数据信息类
     */
    public static class ResourceMetadata {
        private String fileId;
        private long fileSize;
        private String downloadUrl;

        // Getters and setters
        public String getFileId() { return fileId; }
        public ResourceMetadata setFileId(String fileId) {
            this.fileId = fileId;
            return this;
        }

        public long getFileSize() { return fileSize; }
        public ResourceMetadata setFileSize(long fileSize) {
            this.fileSize = fileSize;
            return this;
        }

        public String getDownloadUrl() { return downloadUrl; }
        public ResourceMetadata setDownloadUrl(String downloadUrl) {
            this.downloadUrl = downloadUrl;
            return this;
        }
    }
}