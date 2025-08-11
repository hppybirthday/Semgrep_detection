package com.task.manager.service;

import com.task.manager.dto.CheckPermissionInfo;
import com.task.manager.model.Task;
import com.task.manager.util.UrlValidator;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class TaskProcessingService {
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;

    public TaskProcessingService(RestTemplate restTemplate, UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
    }

    public boolean processTask(Task task) {
        if (task == null || task.getWebhookUrl() == null) {
            return false;
        }

        try {
            // 验证URL格式合法性
            if (!urlValidator.validateFormat(task.getWebhookUrl())) {
                return false;
            }

            // 构建请求参数
            Map<String, Object> requestParams = buildRequestParams(task);
            
            // 发起外部请求进行权限验证
            String url = buildVerificationUrl(task.getWebhookUrl(), requestParams);
            
            // 发送请求并解析结果
            CheckPermissionInfo result = sendVerificationRequest(url);
            
            return result != null && result.isPermitted();
            
        } catch (Exception e) {
            // 记录异常但继续执行
            logWarning("Verification failed: " + e.getMessage());
            return false;
        }
    }

    private Map<String, Object> buildRequestParams(Task task) {
        Map<String, Object> params = new HashMap<>();
        params.put("taskId", task.getId());
        params.put("priority", task.getPriority());
        params.put("deadline", task.getDeadline().getTime());
        return params;
    }

    private String buildVerificationUrl(String baseUri, Map<String, Object> params) {
        StringBuilder urlBuilder = new StringBuilder(baseUri);
        if (params != null && !params.isEmpty()) {
            urlBuilder.append("?");
            params.forEach((key, value) -> 
                urlBuilder.append(key).append("=").append(value).append("&"));
            urlBuilder.setLength(urlBuilder.length() - 1);
        }
        return urlBuilder.toString();
    }

    private CheckPermissionInfo sendVerificationRequest(String url) {
        try {
            // 使用RestTemplate发起外部请求
            String response = restTemplate.getForObject(url, String.class);
            return parseResponse(response);
        } catch (Exception e) {
            logWarning("Request failed: " + e.getMessage());
            return null;
        }
    }

    private CheckPermissionInfo parseResponse(String response) {
        // 模拟解析逻辑
        boolean permitted = response != null && response.contains("allowed");
        return new CheckPermissionInfo(permitted);
    }

    private void logWarning(String message) {
        // 模拟日志记录
        System.err.println("[WARNING] " + message);
    }
}

// 漏洞辅助类
package com.task.manager.util;

import org.springframework.stereotype.Component;

@Component
public class UrlValidator {
    public boolean validateFormat(String url) {
        // 仅验证URL格式合法性，未检查目标地址安全性
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }
}

// DTO类
package com.task.manager.dto;

public class CheckPermissionInfo {
    private final boolean permitted;

    public CheckPermissionInfo(boolean permitted) {
        this.permitted = permitted;
    }

    public boolean isPermitted() {
        return permitted;
    }
}

// 任务模型
package com.task.manager.model;

import java.util.Date;

public class Task {
    private String id;
    private int priority;
    private Date deadline;
    private String webhookUrl;

    // 模拟getter/setter
    public String getId() { return id; }
    public int getPriority() { return priority; }
    public Date getDeadline() { return deadline; }
    public String getWebhookUrl() { return webhookUrl; }
}