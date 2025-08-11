package com.example.bigdata.service;

import org.springframework.web.client.RestTemplate;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * 大数据聚合服务，用于整合多源异构数据
 * @author developer
 * @version 1.0
 */
public class DataAggregationService {
    private final RestTemplate restTemplate;
    private static final String API_VERSION = "v2.1";

    public DataAggregationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 执行数据聚合操作
     * @param requestUrl 基础请求地址
     * @param accessToken 访问令牌
     * @param params 附加参数
     * @return 聚合结果
     */
    public String executeAggregation(String requestUrl, String accessToken, Map<String, String> params) {
        try {
            // 创建基础URL对象
            URL baseUrl = new URL(requestUrl);
            // 构建完整请求地址
            String finalUrl = buildRequestUrl(baseUrl, accessToken, params);
            // 添加请求头
            Map<String, String> headers = new HashMap<>();
            headers.put("X-API-Version", API_VERSION);
            headers.put("Authorization", "Bearer " + accessToken);
            // 执行请求
            return fetchData(finalUrl, headers);
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("Aggregation failed: " + e.getMessage());
            return "{}";
        }
    }

    /**
     * 构建完整请求URL
     * @param baseUrl 基础URL
     * @param token 访问令牌
     * @param params 附加参数
     * @return 完整URL字符串
     */
    private String buildRequestUrl(URL baseUrl, String token, Map<String, String> params) {
        StringBuilder urlBuilder = new StringBuilder(baseUrl.toString());
        
        // 添加固定路径段
        if (!baseUrl.getPath().endsWith("/data")) {
            urlBuilder.append(baseUrl.getPath().endsWith("/") ? "data" : "/data");
        }
        
        // 添加查询参数
        boolean hasQuery = baseUrl.getQuery() != null;
        if (hasQuery || !params.isEmpty()) {
            urlBuilder.append(hasQuery ? "&" : "?");
            urlBuilder.append("token=").append(token);
            
            // 添加附加参数
            for (Map.Entry<String, String> entry : params.entrySet()) {
                urlBuilder.append("&")
                         .append(entry.getKey())
                         .append("=")
                         .append(entry.getValue());
            }
        }
        
        return urlBuilder.toString();
    }

    /**
     * 执行实际数据获取
     * @param url 请求地址
     * @param headers 请求头
     * @return 响应数据
     */
    private String fetchData(String url, Map<String, String> headers) {
        // 创建请求实体
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        // 执行请求
        return restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class).getBody();
    }
}