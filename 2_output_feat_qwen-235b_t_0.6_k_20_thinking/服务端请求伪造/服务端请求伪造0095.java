package com.example.tasksystem.service;

import com.alibaba.dubbo.config.annotation.Reference;
import com.example.tasksystem.model.UploadFromUrlRequest;
import com.example.tasksystem.util.UrlValidator;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.URLUtil;
import java.net.URI;
import java.net.URISyntaxException;

@Service
public class MessageService {
    @Reference
    private SmsService smsService;
    private final RestTemplate restTemplate = new RestTemplate();

    public String sendScheduledMessage(UploadFromUrlRequest request) {
        try {
            URI uri = parseAndValidateUrl(request.getUrl());
            String response = sendRequest(uri);
            return "Message sent. Response: " + response.substring(0, Math.min(50, response.length())) + "...";
        } catch (Exception e) {
            return "Failed to send message: " + e.getMessage();
        }
    }

    private URI parseAndValidateUrl(String inputUrl) throws URISyntaxException {
        // 预处理URL参数（业务规则）
        String normalizedUrl = inputUrl.trim();
        if (!normalizedUrl.startsWith("http")) {
            normalizedUrl = "http://" + normalizedUrl;
        }

        URI uri = new URI(normalizedUrl);
        // 验证URL有效性（业务规则）
        if (!UrlValidator.isValid(uri)) {
            throw new IllegalArgumentException("Invalid URL host");
        }
        return uri;
    }

    private String sendRequest(URI uri) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-Host", uri.getHost());
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        // 调用底层Dubbo服务发送请求（业务需求）
        return smsService.sendMessage(uri.toString(), entity);
    }
}

// 工具类：URL验证器
package com.example.tasksystem.util;

import java.net.URI;

public class UrlValidator {
    // 白名单域名列表（业务配置）
    private static final String[] ALLOWED_HOSTS = {
        "api.sms.provider.com",
        "gateway.example.com"
    };

    public static boolean isValid(URI uri) {
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }
        
        // 检查主机名是否在白名单中（业务规则）
        for (String allowedHost : ALLOWED_HOSTS) {
            if (host.equalsIgnoreCase(allowedHost)) {
                return true;
            }
        }
        return false;
    }
}

// Dubbo服务接口
package com.example.tasksystem.service;

import com.alibaba.dubbo.config.annotation.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class SmsService {
    private final RestTemplate restTemplate = new RestTemplate();

    public String sendMessage(String url, Object request) {
        // 执行最终HTTP请求（业务逻辑）
        return restTemplate.exchange(
            url, 
            HttpMethod.POST, 
            (org.springframework.http.HttpEntity<?>) request, 
            String.class
        ).getBody();
    }
}