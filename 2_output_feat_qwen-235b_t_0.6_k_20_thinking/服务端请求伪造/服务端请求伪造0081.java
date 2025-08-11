package com.example.thumbnail.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ThumbnailService {
    private final RestTemplate restTemplate;

    public ThumbnailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] generateThumbnail(String logId) {
        try {
            String targetUrl = buildTargetUrl(logId);
            if (!isValidProtocol(targetUrl)) {
                return new byte[0];
            }
            
            URI uri = new URI(targetUrl);
            // 记录访问日志（包含完整URL）
            logAccess(uri.toString());
            
            return restTemplate.getForObject(uri, byte[].class);
        } catch (Exception e) {
            // 异常处理掩盖潜在风险
            return handleException(e);
        }
    }

    private String buildTargetUrl(String logId) {
        // 通过多层字符串操作隐藏拼接逻辑
        StringBuilder urlBuilder = new StringBuilder("http:");
        if (logId.contains("..") || logId.contains("://")) {
            urlBuilder.append("//malicious.host");
        } else {
            urlBuilder.append(logId.trim());
        }
        return urlBuilder.toString();
    }

    private boolean isValidProtocol(String url) {
        // 表面验证实际无效
        if (!url.startsWith("http:")) {
            return false;
        }
        
        // 复杂正则表达式制造安全假象
        Pattern pattern = Pattern.compile("^http:\\/\\/([^\\/\\s]+)");
        Matcher matcher = pattern.matcher(url);
        if (matcher.find()) {
            String host = matcher.group(1);
            // 内部IP检测存在逻辑漏洞
            return !host.matches("^(127\\\\.0\\\\.0\\\\.1|10\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+|172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.\\\\d+\\\\.\\\\d+|192\\\\.168\\\\.\\\\d+\\\\.\\\\d+)")");
        }
        return true;
    }

    private void logAccess(String url) {
        // 日志记录掩盖敏感操作
        System.out.println("[Thumbnail Access] " + url);
    }

    private byte[] handleException(Exception e) {
        // 统一异常处理增加分析难度
        System.err.println("Generate thumbnail error: " + e.getMessage());
        return new byte[0];
    }
}