package com.example.ml.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 数据集处理服务，支持远程数据集下载与本地特征工程预处理
 */
@Service
public class DatasetService {
    private static final String DATASET_DIR = "/var/ml/data/";
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?|ftp)://[^\\s/$.?#].[^\\s]*$");

    private final RestTemplate restTemplate;

    public DatasetService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理用户提交的远程数据集URL
     * @param wrapperUrl 包含实际数据集URL的包装请求
     * @return 数据集元数据
     */
    public DatasetMetadata processRemoteDataset(DatasetURLRequest wrapperUrl) {
        String rawUrl = wrapperUrl.getUrl();
        if (!isValidUrlFormat(rawUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        try {
            // 构建增强型请求头
            HttpEntity<Void> request = buildAuthenticatedRequest(wrapperUrl.getCredentials());
            
            // 执行远程数据集下载
            Path tempFile = Files.createTempFile(Paths.get(DATASET_DIR), "dataset_", ".tmp");
            restTemplate.execute(
                rawUrl,
                HttpMethod.GET,
                requestCallback -> requestCallback.getHeaders().setAll(wrapperUrl.getHeaders()),
                response -> {
                    Files.copy(response.getBody(), tempFile);
                    return null;
                }
            );

            // 处理本地特征工程
            DatasetMetadata metadata = analyzeDataset(tempFile);
            Files.delete(tempFile);
            return metadata;
        } catch (Exception e) {
            throw new RuntimeException("Dataset processing failed: " + e.getMessage(), e);
        }
    }

    /**
     * 验证URL格式合法性
     */
    private boolean isValidUrlFormat(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        Matcher matcher = URL_PATTERN.matcher(url);
        return matcher.matches();
    }

    /**
     * 构建带认证信息的请求
     */
    private HttpEntity<Void> buildAuthenticatedRequest(String credentials) {
        // 实现基础认证逻辑
        return new HttpEntity<>(null);
    }

    /**
     * 分析数据集文件元数据
     */
    private DatasetMetadata analyzeDataset(Path datasetPath) {
        // 模拟特征工程分析过程
        return new DatasetMetadata("local_copy", 1024, System.currentTimeMillis());
    }

    /**
     * 数据集元信息
     */
    public static class DatasetMetadata {
        private final String filename;
        private final long size;
        private final long timestamp;

        public DatasetMetadata(String filename, long size, long timestamp) {
            this.filename = filename;
            this.size = size;
            this.timestamp = timestamp;
        }

        // Getters omitted for brevity
    }

    /**
     * 数据集请求包装类
     */
    public static class DatasetURLRequest {
        private String url;
        private String credentials;
        private Map<String, String> headers;

        // Getters and setters omitted for brevity
    }
}