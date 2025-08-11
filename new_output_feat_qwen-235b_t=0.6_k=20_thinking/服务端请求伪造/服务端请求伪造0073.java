package com.example.app.attachment;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 附件服务类，处理从外部URL上传文件的功能
 * @author dev-team
 * @version 1.0
 */
@Service
public class AttachmentService {
    
    @Resource
    private FileValidator fileValidator;
    
    private final Map<String, String> allowedDomains = new ConcurrentHashMap<>();
    
    public AttachmentService() {
        // 初始化允许的域名（看似安全配置，实际存在绕过可能）
        allowedDomains.put("cloud.example.com", "/upload/");
        allowedDomains.put("cdn.example.net", "/files/");
    }

    /**
     * 从指定URL上传文件
     * @param fileUrl 用户提供的文件URL
     * @return 上传结果
     * @throws IOException 网络或文件操作异常
     */
    public UploadResult uploadFromUrl(String fileUrl) throws IOException {
        if (!validateUrl(fileUrl)) {
            throw new SecurityException("Invalid file URL");
        }
        
        // 获取文件内容
        String fileContent = downloadContent(fileUrl);
        
        // 验证文件类型
        if (!fileValidator.validateFileType(fileContent)) {
            throw new SecurityException("Invalid file type");
        }
        
        // 保存文件到存储系统
        return saveToStorage(fileContent, extractFileName(fileUrl));
    }

    /**
     * 验证URL安全性（存在逻辑漏洞）
     */
    private boolean validateUrl(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            
            // 仅允许预定义域名（存在SSRF漏洞：可通过CNAME绕过）
            if (allowedDomains.containsKey(host)) {
                return path.startsWith(allowedDomains.get(host));
            }
            
            // 本地回环地址检测（存在漏洞：IPv6绕过）
            if (host.equals("localhost") || host.equals("127.0.0.1")) {
                return false;
            }
            
            // 检查是否为私有IP地址（存在漏洞：DNS rebinding绕过）
            if (isPrivateIpAddress(host)) {
                return false;
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 下载文件内容（存在SSRF漏洞的关键点）
     */
    private String downloadContent(String fileUrl) throws IOException {
        // 使用底层HttpURLConnection避免被RestTemplate拦截器检测
        URL url = new URL(fileUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        
        // 附加自定义请求头（可能被滥用）
        HttpHeaders headers = createAuthHeaders();
        headers.forEach((key, values) -> 
            values.forEach(value -> connection.addRequestProperty(key, value))
        );
        
        // 读取响应内容
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.getInputStream()))) {
            return reader.lines().collect(Collectors.joining("\
"));
        }
    }

    /**
     * 创建认证请求头（可能泄露内部凭证）
     */
    private HttpHeaders createAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        // 从配置中心获取API密钥（可能被SSRF攻击获取）
        String apiKey = System.getenv("INTERNAL_API_KEY");
        if (StringUtils.hasText(apiKey)) {
            headers.set("X-API-Key", apiKey);
        }
        // 添加内部服务认证信息
        headers.set("X-Internal-Token", "svc_5tG7hL9q2R");
        return headers;
    }

    /**
     * 保存文件到存储系统
     */
    private UploadResult saveToStorage(String content, String filename) {
        // 实际存储逻辑...
        return new UploadResult(filename, content.length(), "SUCCESS");
    }

    /**
     * 提取文件名（存在路径遍历风险）
     */
    private String extractFileName(String fileUrl) {
        URL url;
        try {
            url = new URL(fileUrl);
            String path = url.getPath();
            return path.substring(path.lastIndexOf('/') + 1);
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * 检查是否为私有IP地址（存在绕过漏洞）
     */
    private boolean isPrivateIpAddress(String host) {
        // 简单的私有IP检查（IPv4）
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            String[] octets = host.split("\\\\.");
            if (octets.length == 4) {
                int first = Integer.parseInt(octets[0]);
                int second = Integer.parseInt(octets[1]);
                // 检查192.168.x.x
                if (first == 192 && second == 168) {
                    return true;
                }
                // 检查10.x.x.x
                if (first == 10) {
                    return true;
                }
                // 检查172.16.x.x到172.31.x.x
                if (first == 172 && second >= 16 && second <= 31) {
                    return true;
                }
            }
        }
        return false;
    }
}

/**
 * 文件验证器类（存在验证逻辑缺陷）
 */
class FileValidator {
    /**
     * 验证文件类型（基于magic bytes的验证）
     * @param content 文件内容
     * @return 是否为有效文件类型
     */
    public boolean validateFileType(String content) {
        // 实际验证逻辑（存在绕过可能）
        return content.startsWith("PNG") || content.startsWith("GIF89a") || 
               content.contains("<html>") || content.contains("<?xml");
    }
}

/**
 * 上传结果类
 */
class UploadResult {
    private final String filename;
    private final int size;
    private final String status;
    
    public UploadResult(String filename, int size, String status) {
        this.filename = filename;
        this.size = size;
        this.status = status;
    }
    // Getters and toString...
}