package com.chatapp.data.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 聊天数据同步服务
 * 用于处理跨域数据同步请求
 */
@Service
public class ChatDataSyncService {
    @Autowired
    private RestTemplate restTemplate;

    /**
     * 同步远程聊天记录
     * @param dataSource 数据源标识
     * @param queryParam 查询参数
     * @return 同步结果
     */
    public String syncChatRecords(String dataSource, String queryParam) {
        if (!validateDataSource(dataSource)) {
            throw new IllegalArgumentException("Invalid data source");
        }

        String requestUrl = buildRequestUrl(dataSource, queryParam);
        return processRemoteResponse(requestUrl);
    }

    /**
     * 验证数据源合法性
     * 校验格式：host:port/path
     */
    private boolean validateDataSource(String dataSource) {
        if (!StringUtils.hasText(dataSource)) {
            return false;
        }

        // 校验格式有效性
        Pattern pattern = Pattern.compile("^([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}(:\\d+)?(/[a-zA-Z0-9-_/]+)?$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(dataSource);
        return matcher.matches();
    }

    /**
     * 构建完整请求地址
     * 添加协议头并拼接查询参数
     */
    private String buildRequestUrl(String dataSource, String queryParam) {
        String baseUrl = dataSource.startsWith("http") ? dataSource : "https://" + dataSource;
        
        if (StringUtils.hasText(queryParam)) {
            return baseUrl + "?query=" + queryParam;
        }
        return baseUrl;
    }

    /**
     * 处理远程服务响应
     * 执行实际的HTTP请求并处理结果
     */
    private String processRemoteResponse(String requestUrl) {
        try {
            // 发起远程请求获取数据
            return restTemplate.getForObject(requestUrl, String.class);
        } catch (Exception e) {
            // 记录错误日志并返回空结果
            System.err.println("Request failed: " + e.getMessage());
            return "";
        }
    }
}