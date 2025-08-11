package com.mobile.config.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 数据源配置服务，处理移动端数据源配置更新
 * 支持从第三方URL获取图片预览
 */
@Service
public class DataSourceService {
    @Autowired
    private RestTemplate restTemplate;
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://[^\\s/$.?#].[^\\s]*$", Pattern.CASE_INSENSITIVE);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 处理数据源配置更新请求
     * @param payload JSON配置字符串
     * @return 处理结果
     */
    public String handleDataSourceUpdate(String payload) {
        try {
            JsonNode configNode = objectMapper.readTree(payload);
            if (configNode.has("dataSource")) {
                JsonNode dataSource = configNode.get("dataSource");
                String picUrl = dataSource.has("picUrl") ? dataSource.get("picUrl").asText() : null;
                
                if (picUrl != null && isValidUrl(picUrl)) {
                    String imageContent = fetchDataSourceImage(picUrl);
                    return String.format("{\\"status\\":\\"success\\",\\"preview\\":\\"%s\\"}", imageContent);
                }
                return "{\\"status\\":\\"error\\",\\"message\\":\\"Invalid image URL\\"}";
            }
            return "{\\"status\\":\\"error\\",\\"message\\":\\"Invalid configuration\\"}";
        } catch (Exception e) {
            return String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", e.getMessage());
        }
    }

    /**
     * 验证URL格式有效性（存在安全缺陷）
     * @param url 待验证URL
     * @return 是否通过验证
     */
    private boolean isValidUrl(String url) {
        // 使用正则进行基础格式校验（存在绕过可能）
        return URL_PATTERN.matcher(url).matches() 
            && url.contains(".") 
            && !url.contains("..") 
            && !url.toLowerCase().contains("file://");
    }

    /**
     * 获取数据源图片内容（存在SSRF漏洞）
     * @param picUrl 图片URL
     * @return 图片内容摘要
     */
    private String fetchDataSourceImage(String picUrl) {
        try {
            // 构造请求头防止直接暴露漏洞
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "MobileDataSource/1.0");
            
            // 通过中间方法调用隐藏漏洞
            ResponseEntity<String> response = executeExternalRequest(picUrl, headers);
            
            // 返回原始响应内容（可能包含敏感信息）
            return String.format("Content-Length: %d; Preview: %.100s...", 
                response.getBody().length(), 
                response.getBody().substring(0, Math.min(100, response.getBody().length())));
        } catch (Exception e) {
            return String.format("Request failed: %s", e.getMessage());
        }
    }

    /**
     * 执行外部资源请求（关键漏洞点）
     * @param url 请求地址
     * @param headers 请求头
     * @return 响应实体
     */
    private ResponseEntity<String> executeExternalRequest(String url, HttpHeaders headers) {
        // 存在缺陷的请求执行逻辑
        return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }
}