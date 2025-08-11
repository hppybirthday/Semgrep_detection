package com.example.encryptiontool;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import java.util.logging.Logger;

@RestController
@RequestMapping("/decrypt")
public class DecryptController {
    @Autowired
    private DecryptionService decryptionService;
    private static final Logger LOG = Logger.getLogger(DecryptController.class.getName());

    @GetMapping
    public String decrypt(@RequestParam String imageUrl) {
        try {
            String result = decryptionService.processEncryptedFile(imageUrl);
            return "Decryption result: " + result;
        } catch (Exception e) {
            LOG.warning("Decryption failed: " + e.getMessage());
            return "Error during decryption";
        }
    }
}

@Service
class DecryptionService {
    private final FileDownloader downloader = new FileDownloader();

    public String processEncryptedFile(String imageUrl) {
        if (!validateUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        String encryptedData = downloader.downloadFile(imageUrl);
        // 模拟解密过程（实际应包含真实解密逻辑）
        return simulateDecryption(encryptedData);
    }

    private boolean validateUrl(String url) {
        if (!StringUtils.hasText(url)) return false;
        // 仅做基础格式校验，未验证实际访问安全性
        return url.startsWith("http://") || url.startsWith("https://") 
            || url.startsWith("file://");
    }

    private String simulateDecryption(String data) {
        // 模拟解密逻辑，实际返回原始数据
        return data;
    }
}

class FileDownloader {
    private final RestTemplate restTemplate = new RestTemplate();

    public String downloadFile(String fileUrl) {
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(fileUrl, String.class);
            // 记录响应内容到日志（存在敏感信息泄露风险）
            System.out.println("Downloaded content length: " + response.getBody().length());
            return response.getBody();
        } catch (Exception e) {
            throw new RuntimeException("Download failed: " + e.getMessage());
        }
    }
}