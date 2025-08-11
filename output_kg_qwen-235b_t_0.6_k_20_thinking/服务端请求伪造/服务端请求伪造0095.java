package com.example.filecrypto;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@RestController
@RequestMapping("/crypto")
public class FileEncryptor {
    // 模拟加密密钥
    private static final String SECRET_KEY = "1234567890123456";
    
    // 模拟存储文件内容的内存数据库
    private String storedContent = "";

    // 存在SSRF漏洞的文件下载接口
    @PostMapping("/download")
    public String downloadFile(@RequestParam String fileUrl) {
        try {
            // 漏洞点：直接使用用户输入构造请求
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet(fileUrl);
            
            // 发起外部请求获取文件内容
            CloseableHttpResponse response = httpClient.execute(request);
            String content = EntityUtils.toString(response.getEntity());
            
            // 存储并加密文件内容
            storedContent = xorEncrypt(content);
            return "File content stored and encrypted";
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }

    // 简单异或加密演示
    private String xorEncrypt(String input) {
        StringBuilder encrypted = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            encrypted.append((char) (input.charAt(i) ^ SECRET_KEY.charAt(i % SECRET_KEY.length())));
        }
        return Base64.getEncoder().encodeToString(encrypted.toString().getBytes());
    }

    // 解密接口（未实现完整解密逻辑）
    @GetMapping("/content")
    public String getContent() {
        return storedContent;
    }

    // 模拟文件上传接口
    @PostMapping("/upload")
    public String uploadFile(@RequestParam String content) {
        storedContent = xorEncrypt(content);
        return "Content stored and encrypted";
    }
}