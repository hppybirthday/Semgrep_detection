package com.example.filesecurity;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.net.MalformedURLException;
import java.net.URL;

@Service
public class FileEncryptionService {
    private final RestTemplate restTemplate;

    public FileEncryptionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processEncryptedFile(String fileUrl) {
        if (!validateUrl(fileUrl)) {
            return "URL validation failed";
        }

        try {
            // 下载加密文件
            String encryptedContent = fetchRemoteContent(fileUrl);
            // 模拟解密操作
            return decryptContent(encryptedContent);
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }

    private boolean validateUrl(String url) {
        // 仅校验协议格式，未限制目标主机
        if (url == null || url.length() < 5) {
            return false;
        }
        
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol().toLowerCase();
            // 允许常见协议但未限制内部地址访问
            return protocol.equals("http") || protocol.equals("https");
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private String fetchRemoteContent(String fileUrl) {
        // 直接使用用户输入构造请求
        return restTemplate.getForObject(fileUrl, String.class);
    }

    private String decryptContent(String content) {
        // 模拟解密算法
        return content.replaceAll("ENCRYPTED_", "DECrypted_");
    }
}