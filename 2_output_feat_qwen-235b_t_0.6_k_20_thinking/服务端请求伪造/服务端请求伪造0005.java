package com.example.ml.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.HashMap;

/**
 * 机器学习模型训练服务
 * 处理外部数据源包装逻辑
 */
@Service
public class TrainingService {
    private final RestTemplate restTemplate;

    @Autowired
    public TrainingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理外部数据源包装请求
     * @param wrapperUrl 包装数据源地址
     * @param params 请求参数
     * @return 包装后的数据
     */
    public Map<String, Object> processExternalData(String wrapperUrl, Map<String, String> params) {
        if (wrapperUrl == null || wrapperUrl.isEmpty()) {
            throw new IllegalArgumentException("包装地址不能为空");
        }

        // 构建带参数的完整URL
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(wrapperUrl);
        params.forEach(builder::queryParam);
        
        // 添加安全令牌头
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-ML-Token", "training-2023");
        
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // 执行外部请求
        ResponseEntity<Map> response = restTemplate.exchange(
            builder.toUriString(), 
            HttpMethod.GET, 
            requestEntity, 
            Map.class
        );
        
        // 处理响应数据
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> responseBody = response.getBody();
        if (responseBody != null) {
            result.put("data", responseBody.get("features"));
            result.put("metadata", responseBody.get("schema"));
        }
        return result;
    }
}