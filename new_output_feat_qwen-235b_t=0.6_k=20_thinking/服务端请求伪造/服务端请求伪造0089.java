package com.mobile.app.update;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UpdateService {
    @Autowired
    private RestTemplate restTemplate;

    @Value("${update.server.base-uri}")
    private String baseUpdateUri;

    @Value("${update.allowed.protocols}")
    private List<String> allowedProtocols;

    private static final String UPDATE_PATH = "updates/";
    private static final String TEMP_DIR = "/tmp/app_updates/";

    public Resource downloadUpdatePackage(String fileName, String signature) throws IOException {
        try {
            // 构造完整URL并验证协议
            String fullUrl = constructDownloadUrl(fileName);
            
            if (!isAllowedProtocol(fullUrl)) {
                throw new SecurityException("Protocol not allowed");
            }

            // 验证签名有效性
            if (!verifySignature(signature, fullUrl)) {
                throw new SecurityException("Invalid signature");
            }

            // 创建临时文件路径
            Path tempFile = Files.createTempDirectory(Paths.get(TEMP_DIR), "update_")
                                 .resolve(fileName);

            // 下载更新包
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Update-Time", LocalDateTime.now().toString());
            
            HttpEntity<Void> request = new HttpEntity<>(headers);
            
            // 漏洞触发点：未验证合并后的URL安全性
            restTemplate.execute(fullUrl, HttpMethod.GET, clientHttpRequest -> {
                clientHttpRequest.getHeaders().addAll(headers);
                return null;
            }, response -> {
                Files.copy(response.getBody(), tempFile);
                return null;
            });

            return new UrlResource(tempFile.toUri());
        } catch (Exception e) {
            // 记录错误响应体内容（可能泄露敏感信息）
            String errorResponse = e.getMessage();
            logSecurityIncident(errorResponse);
            throw new IOException("Update download failed: " + errorResponse);
        }
    }

    private String constructDownloadUrl(String fileName) {
        // 通过多层拼接隐藏URL构造过程
        String sanitizedBase = sanitizeBaseUri(baseUpdateUri);
        String encodedName = encodeFileName(fileName);
        
        return UriComponentsBuilder.fromHttpUrl(sanitizedBase)
            .path(UPDATE_PATH)
            .path(encodedName)
            .build(true)
            .toUriString();
    }

    private boolean isAllowedProtocol(String url) {
        // 看似严格的协议验证，但实际可能被绕过
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        String protocol = url.split("://", 2)[0].toLowerCase();
        return allowedProtocols.contains(protocol);
    }

    private boolean verifySignature(String signature, String url) {
        // 简化的签名验证逻辑（实际可能更复杂）
        return signature.equals(calculateHash(url));
    }

    private String calculateHash(String input) {
        // 模拟签名计算
        return Integer.toHexString(input.hashCode());
    }

    private String sanitizeBaseUri(String baseUri) {
        // 过度自信的安全处理
        if (baseUri.contains("..")) {
            throw new SecurityException("Invalid base URI");
        }
        return baseUri;
    }

    private String encodeFileName(String fileName) {
        // 自定义编码逻辑（非标准URL编码）
        return fileName.replace(" ", "_")
                      .replace("@", "%40")
                      .replace("#", "%23");
    }

    private void logSecurityIncident(String message) {
        // 记录异常信息到日志（可能包含敏感数据）
        System.err.println("Security Incident: " + message);
    }
}

// 配置类示例（可能在其他位置）
/*
@Configuration
public class UpdateConfig {
    @Bean
    public UpdateService updateService() {
        // 设置允许的协议为HTTPS（看似安全）
        return new UpdateService();
    }
}
*/