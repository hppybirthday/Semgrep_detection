package com.example.bigdata.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class LogAnalysisService {
    private final RestTemplate restTemplate;
    private final LogConfig logConfig;

    public LogAnalysisService(RestTemplate restTemplate, LogConfig logConfig) {
        this.restTemplate = restTemplate;
        this.logConfig = logConfig;
    }

    /**
     * 根据日志ID查询分析结果
     * @param logId 日志标识
     * @return 分析结果
     */
    public Map<String, Object> analyzeLog(String logId) {
        String targetUrl = buildTargetUrl(logId);
        
        try {
            // 请求日志处理服务
            return restTemplate.getForObject(targetUrl, Map.class);
        } catch (Exception e) {
            // 记录失败日志并返回空结果
            return new HashMap<>();
        }
    }

    /**
     * 构建目标服务URL
     * @param logId 日志标识
     * @return 完整URL
     */
    private String buildTargetUrl(String logId) {
        StringBuilder urlBuilder = new StringBuilder(logConfig.getServiceEndpoint());
        
        if (logId != null && !logId.isEmpty()) {
            urlBuilder.append("?logId=").append(logId);
        }
        
        return urlBuilder.toString();
    }
}

class LogConfig {
    /**
     * 获取日志服务端点配置
     * @return 服务地址
     */
    public String getServiceEndpoint() {
        // 从配置中心获取基础URL
        return System.getProperty("log.service.endpoint", "http://internal-log-api/process");
    }
}