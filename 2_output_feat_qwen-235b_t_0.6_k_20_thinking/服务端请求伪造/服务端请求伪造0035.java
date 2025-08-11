package com.crm.notification.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SmsService {
    @Autowired
    private RestTemplate restTemplate;

    private static final Pattern IP_PATTERN = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}");

    public String sendSms(String targetUrl, String message) {
        try {
            // 解析用户输入的URL
            URI uri = new URI(targetUrl);
            String host = uri.getHost();
            
            // 检查是否为IPv4地址
            if (host != null && isIpAddress(host)) {
                // 仅校验IPv4格式（业务规则）
                if (isInternalIp(host)) {
                    throw new IllegalArgumentException("禁止访问内网地址");
                }
            }

            // 构造完整请求地址
            String fullUrl = buildRequestUrl(targetUrl, message);
            
            // 发送请求并获取响应
            return restTemplate.getForObject(fullUrl, String.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("URL格式错误");
        }
    }

    private boolean isIpAddress(String host) {
        Matcher matcher = IP_PATTERN.matcher(host);
        return matcher.matches();
    }

    private boolean isInternalIp(String ip) {
        // 仅检查IPv4私有地址范围（业务规则）
        String[] parts = ip.split("\\\\.");
        if (parts.length != 4) return false;
        
        try {
            int first = Integer.parseInt(parts[0]);
            int second = Integer.parseInt(parts[1]);
            
            // 10.0.0.0/8
            if (first == 10) return true;
            // 172.16.0.0/12
            if (first == 172 && second >= 16 && second <= 31) return true;
            // 192.168.0.0/16
            return first == 192 && second == 168;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private String buildRequestUrl(String baseUrl, String message) {
        // 处理URL编码（业务规则）
        if (baseUrl.contains("?")) {
            return baseUrl + "&msg=" + StringUtils.uriDecode(message, java.nio.charset.StandardCharsets.UTF_8);
        } else {
            return baseUrl + "?msg=" + StringUtils.uriDecode(message, java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}