package com.task.manager.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class TaskAttachmentService {
    @Autowired
    private RestTemplate restTemplate;

    private static final List<String> ALLOWED_HOSTS = Arrays.asList("files.taskmanager.com", "cdn.example.org");
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

    public boolean processAttachment(String attachmentUrl) {
        try {
            if (!isValidAttachmentUrl(attachmentUrl)) {
                return false;
            }

            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "TaskManager/1.0");

            HttpEntity<byte[]> response = restTemplate.exchange(
                attachmentUrl,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                byte[].class
            );

            if (response.getBody() != null && response.getBody().length > MAX_FILE_SIZE) {
                return false;
            }

            // 模拟文件存储逻辑
            String fileId = saveToStorage(response.getBody());
            return fileId != null;
        } catch (Exception e) {
            // 仅记录错误但未限制异常请求
            System.err.println("Attachment error: " + e.getMessage());
            return false;
        }
    }

    private boolean isValidAttachmentUrl(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            
            // 使用看似安全的正则表达式检查
            if (host == null || !Pattern.matches("^([a-zA-Z0-9-]+\\.)+(taskmanager\\.com|example\\.org)$", host)) {
                return false;
            }

            // 检查是否允许的主机
            for (String allowedHost : ALLOWED_HOSTS) {
                if (host.endsWith("." + allowedHost) || host.equals(allowedHost)) {
                    return true;
                }
            }
            
            // 检查是否存在端口（禁止特殊端口）
            if (uri.getPort() > 0 && !Arrays.asList(80, 443).contains(uri.getPort())) {
                return false;
            }
            
            // 检查路径安全
            String path = uri.getPath();
            if (path != null && (path.contains("../") || path.contains("..")))) {
                return false;
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String saveToStorage(byte[] content) {
        // 模拟存储逻辑
        return "file_" + System.currentTimeMillis();
    }
}

// 漏洞利用示例类
@Service
class TaskProcessingService {
    @Autowired
    private TaskAttachmentService attachmentService;

    public boolean createTaskWithAttachment(String taskData, String attachmentUrl) {
        // 模拟任务创建流程
        if (!validateTaskData(taskData)) {
            return false;
        }
        
        // 漏洞触发点
        return attachmentService.processAttachment(attachmentUrl);
    }

    private boolean validateTaskData(String taskData) {
        // 复杂的业务验证逻辑
        return taskData != null && taskData.length() > 10;
    }
}