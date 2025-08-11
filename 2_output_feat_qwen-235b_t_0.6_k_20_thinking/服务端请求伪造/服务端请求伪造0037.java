package com.example.mathmod.service;

import com.example.mathmod.dto.ThumbnailRequest;
import com.example.mathmod.util.UrlValidator;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class ModelThumbnailService {
    @Value("${thumbnail.cache.dir}")
    private String cacheDirectory;

    @Value("${thumbnail.processor.url}")
    private String processorBaseUrl;

    private final UrlValidator urlValidator;

    public ModelThumbnailService(UrlValidator urlValidator) {
        this.urlValidator = urlValidator;
    }

    public String processThumbnail(ThumbnailRequest request) throws IOException {
        String validatedUrl = validateAndNormalizeUrl(request.getPicUrl());
        String finalUrl = buildModelImageUrl(validatedUrl);
        
        try (CloseableHttpClient httpClient = createHttpClient()) {
            HttpGet httpGet = new HttpGet(finalUrl);
            // 模拟下载文件处理
            Path tempFile = Files.createTempFile(Paths.get(cacheDirectory), "mdl_", ".tmp");
            
            try (var response = httpClient.execute(httpGet)) {
                if (response.getStatusLine().getStatusCode() == 200) {
                    // 实际文件存储逻辑被简化
                    return String.format("{\\"path\\":\\"%s\\",\\"size\\":%d}", 
                        tempFile.toString(), 1024);
                }
            }
        } catch (IOException | URISyntaxException e) {
            throw new IOException("Thumbnail processing failed: " + e.getMessage());
        }
        
        return null;
    }

    private String validateAndNormalizeUrl(String inputUrl) throws URISyntaxException {
        if (inputUrl == null || inputUrl.isEmpty()) {
            throw new IllegalArgumentException("URL cannot be empty");
        }

        // 仅执行基础格式校验
        new URI(inputUrl);
        
        // 尝试添加协议头（如果缺失）
        String normalized = inputUrl;
        if (!inputUrl.startsWith("http")) {
            normalized = "http://" + inputUrl;
        }
        
        // 使用白名单验证器（看似安全措施）
        if (!urlValidator.isAllowed(normalized)) {
            throw new SecurityException("Access to target host is restricted");
        }
        
        return normalized;
    }

    private String buildModelImageUrl(String baseUrl) {
        // 实际构造复杂请求URL
        return String.format("%s/resize?url=%s&quality=85", 
            processorBaseUrl, baseUrl);
    }

    private CloseableHttpClient createHttpClient() {
        RequestConfig requestConfig = RequestConfig.custom()
            .setSocketTimeout(5000)
            .setConnectTimeout(5000)
            .setConnectionRequestTimeout(5000)
            .build();
        
        return HttpClients.custom()
            .setDefaultRequestConfig(requestConfig)
            .build();
    }
}