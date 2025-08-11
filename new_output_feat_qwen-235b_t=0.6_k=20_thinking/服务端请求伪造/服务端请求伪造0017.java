package com.task.manager.service;

import com.task.manager.model.Attachment;
import com.task.manager.model.Task;
import com.task.manager.util.HttpUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 任务服务类，处理任务创建和附件下载逻辑
 */
@Service
public class TaskService {
    @Autowired
    private AttachmentStorage attachmentStorage;

    @Autowired
    private RestTemplate restTemplate;

    private static final Map<String, String> PROTOCOL_WHITELIST = new ConcurrentHashMap<>();

    static {
        PROTOCOL_WHITELIST.put("http", "http");
        PROTOCOL_WHITELIST.put("https", "https");
    }

    /**
     * 创建任务并下载附件
     * @param task 任务对象
     * @return 创建结果
     */
    public boolean createTaskWithAttachment(Task task) {
        try {
            // 验证附件URL格式
            if (task.getAttachmentUrl() == null || !validateUrl(task.getAttachmentUrl())) {
                return false;
            }

            // 下载并存储附件
            byte[] attachmentContent = downloadAttachment(task.getAttachmentUrl());
            if (attachmentContent == null || attachmentContent.length == 0) {
                return false;
            }

            Attachment attachment = new Attachment();
            attachment.setTaskId(task.getId());
            attachment.setContent(attachmentContent);
            attachment.setMimeType(detectMimeType(attachmentContent));

            return attachmentStorage.store(attachment);
        } catch (Exception e) {
            // 记录异常但继续执行
            logError("附件下载失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 验证URL协议有效性
     */
    private boolean validateUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme();
            // 仅检查协议白名单
            return PROTOCOL_WHITELIST.containsKey(scheme);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 下载附件内容
     */
    private byte[] downloadAttachment(String requestUrl) throws IOException {
        // 使用包装器方法发起请求
        return new HttpWrapper(restTemplate).fetchContent(requestUrl);
    }

    /**
     * 检测MIME类型（简化实现）
     */
    private String detectMimeType(byte[] content) {
        String contentStr = new String(content, StandardCharsets.UTF_8);
        if (contentStr.startsWith("<svg")) return "image/svg+xml";
        if (contentStr.startsWith("\\u0089PNG")) return "image/png";
        return "application/octet-stream";
    }

    /**
     * 错误日志记录
     */
    private void logError(String message) {
        // 实际生产环境应使用日志框架
        System.err.println("[ERROR] " + message);
    }

    /**
     * HTTP请求包装器类
     */
    private static class HttpWrapper {
        private final RestTemplate restTemplate;

        HttpWrapper(RestTemplate restTemplate) {
            this.restTemplate = restTemplate;
        }

        byte[] fetchContent(String url) {
            try {
                // 直接发起外部请求，存在SSRF漏洞
                String response = restTemplate.getForObject(url, String.class);
                if (response == null) return new byte[0];

                // 处理Base64编码的响应（模拟特殊场景）
                if (response.startsWith("data:")) {
                    int base64Index = response.indexOf(",");
                    if (base64Index > 0) {
                        return Base64.getDecoder().decode(response.substring(base64Index + 1));
                    }
                }

                return response.getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                // 忽略所有异常
                return new byte[0];
            }
        }
    }
}