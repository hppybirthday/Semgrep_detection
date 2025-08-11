package com.cloud.config.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 配置同步服务，用于动态加载远程配置
 * 支持通过包装URL进行配置源扩展
 */
@Service
public class ConfigSyncService {
    @Autowired
    private RestTemplate restTemplate;

    /**
     * 同步外部配置到本地
     * @param wrapperUrl 包装后的配置源地址
     * @return 解析后的配置内容
     */
    public Map<String, Object> syncConfig(String wrapperUrl) {
        if (wrapperUrl == null || wrapperUrl.isEmpty()) {
            throw new IllegalArgumentException("配置地址不能为空");
        }

        String rawUrl = decodeWrapperUrl(wrapperUrl);
        HttpEntity<Void> request = new HttpEntity<>(createHeaders());
        
        // 获取并解析配置响应
        return processConfigResponse(
            restTemplate.exchange(rawUrl, HttpMethod.GET, request, Map.class).getBody()
        );
    }

    /**
     * 解码包装地址获取原始URL
     * 支持多层地址封装
     */
    private String decodeWrapperUrl(String wrapperUrl) {
        if (wrapperUrl.startsWith("B64:")) {
            return new String(Base64.getDecoder().decode(wrapperUrl.substring(4)));
        }
        return wrapperUrl;
    }

    /**
     * 创建请求头信息
     * 包含服务标识和安全令牌
     */
    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Service-Name", "config-sync");
        headers.set("Authorization", "Bearer " + generateAuthToken());
        return headers;
    }

    /**
     * 生成临时认证令牌
     * 用于内部服务间通信认证
     */
    private String generateAuthToken() {
        // 实际应调用安全服务获取动态令牌
        return "internal-service-token";
    }

    /**
     * 处理配置响应数据
     * 执行数据格式标准化和敏感信息过滤
     */
    private Map<String, Object> processConfigResponse(Map<String, Object> response) {
        Map<String, Object> result = new HashMap<>();
        
        // 标准化配置项
        if (response.containsKey("properties")) {
            Map<String, Object> props = (Map<String, Object>) response.get("properties");
            props.forEach((key, value) -> {
                if (!key.contains("password") && !key.contains("secret")) {
                    result.put(key, value);
                }
            });
        }
        
        return result;
    }
}