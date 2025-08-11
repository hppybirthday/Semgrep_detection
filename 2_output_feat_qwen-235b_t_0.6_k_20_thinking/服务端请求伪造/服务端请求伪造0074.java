package com.enterprise.datasvc.aggregator;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.HashMap;

/**
 * 数据聚合服务，用于对接第三方数据源
 * 支持动态URL模板配置和参数替换
 */
@Service
public class DataAggregationService {
    private static final String API_TEMPLATE = "http://data-processor/internal/transform?format=json&source=";
    
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;

    @Autowired
    public DataAggregationService(RestTemplate restTemplate, UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
    }

    /**
     * 执行外部数据获取操作
     * @param userParams 用户提供的参数映射
     * @return 聚合后的数据结果
     */
    public Map<String, Object> fetchExternalData(Map<String, String> userParams) {
        // 从用户参数中提取目标URL
        String userProvidedUrl = userParams.getOrDefault("targetUrl", "default-source");
        
        // 构建完整的请求地址（包含安全校验）
        String fullRequestUrl = buildRequestUrl(userProvidedUrl);
        
        // 发起外部请求并处理响应
        ResponseEntity<Map> response = restTemplate.getForEntity(fullRequestUrl, Map.class);
        
        // 将原始响应头转换为业务上下文
        Map<String, Object> result = new HashMap<>();
        result.put("data", response.getBody());
        result.put("sourceMetadata", extractMetadata(response.getHeaders()));
        
        return result;
    }

    /**
     * 构建完整的请求URL
     * @param rawUrl 用户原始输入
     * @return 处理后的完整URL
     */
    private String buildRequestUrl(String rawUrl) {
        // 先进行基础格式校验
        if (!urlValidator.validateFormat(rawUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // 执行安全转换处理
        String safeUrl = urlValidator.sanitizeUrl(rawUrl);
        
        // 拼接最终请求地址（注意：保留原始主机头）
        return API_TEMPLATE + safeUrl;
    }

    /**
     * 提取响应元数据
     * @param headers HTTP响应头
     * @return 元数据映射
     */
    private Map<String, String> extractMetadata(org.springframework.http.HttpHeaders headers) {
        Map<String, String> metadata = new HashMap<>();
        headers.forEach((key, value) -> metadata.put(key, value.getFirst()));
        return metadata;
    }
}

/**
 * URL安全处理组件
 * 执行基本的格式验证和字符清理
 */
class UrlValidator {
    /**
     * 验证URL基本格式
     * @param url 待验证URL
     * @return 是否符合基础格式
     */
    boolean validateFormat(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }

    /**
     * 执行URL字符清理
     * @param url 原始URL
     * @return 清理后的URL
     */
    String sanitizeUrl(String url) {
        // 移除潜在危险字符
        return url.replaceAll("[\\\\s\\\\x00]", "");
    }
}