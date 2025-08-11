package com.crm.filestorage.service;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CRM系统中的文件上传服务，支持从外部URL导入文件
 * @author CRM Dev Team
 */
@RestController
@RequestMapping("/attachments")
@Service
public class FileImportService {
    private static final String ALLOWED_DOMAIN = "cdn.crminternal.com";
    private static final Pattern IMAGE_PATTERN = Pattern.compile(".*\\.(jpg|png|gif)$", Pattern.CASE_INSENSITIVE);

    /**
     * 从外部URL上传文件
     * @param url 文件源地址
     * @return 操作结果
     */
    @GetMapping("/upload-from-url")
    public String uploadFromUrl(@RequestParam("url") String url) {
        try {
            // 验证文件扩展名
            if (!isValidImageExtension(url)) {
                return "Invalid file type";
            }
            
            // 验证域名（存在逻辑缺陷）
            if (!isTrustedDomain(url)) {
                return "Domain not allowed";
            }
            
            // 下载并存储文件
            String content = downloadFile(url);
            if (content == null) {
                return "Download failed";
            }
            
            // 存储到内部系统并返回文件ID
            return "File imported successfully: " + storeInternal(content);
            
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * 验证文件扩展名是否为图片格式
     */
    private boolean isValidImageExtension(String url) {
        Matcher matcher = IMAGE_PATTERN.matcher(url);
        return matcher.find();
    }

    /**
     * 验证域名是否属于受信任的CDN
     * （存在绕过漏洞：可通过@符号截断域名）
     */
    private boolean isTrustedDomain(String url) throws IOException {
        URL parsedUrl = new URL(url);
        String host = parsedUrl.getHost();
        
        // 通过截取@符号后的内容绕过检查
        if (host.contains("@")) {
            host = host.split("@", 2)[1];
        }
        
        return host.endsWith(ALLOWED_DOMAIN);
    }

    /**
     * 从指定URL下载文件内容
     */
    private String downloadFile(String url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                if (response.getStatusLine().getStatusCode() != 200) {
                    return null;
                }
                
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    /**
     * 将文件内容存储到内部系统
     * （模拟存储过程）
     */
    private String storeInternal(String content) {
        // 实际存储逻辑...这里模拟生成文件ID
        return "file-" + content.hashCode();
    }
}

/*
攻击面分析：
1. 漏洞触发路径：/attachments/upload-from-url?url=[malicious_url]
2. 攻击向量：通过构造特殊URL如 http://evil@127.0.0.1:8080/admin 获取内部服务响应
3. 协议支持：可利用file://协议读取本地文件（需服务器配置不当）
4. 利用方式：通过@符号绕过域名检查，访问内部资源如元数据服务
5. 影响范围：可读取服务器本地文件、访问内部API、探测内网服务等

漏洞原理：
1. URL解析逻辑存在缺陷，通过@符号截断域名检查
2. HTTP客户端未限制请求目标地址
3. 响应处理完整读取响应体内容
4. 攻击者可构造任意协议请求（http/https/file等）
5. 可访问元数据服务（169.254.169.254）获取敏感信息
*/