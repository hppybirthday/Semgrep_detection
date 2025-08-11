package com.chatapp.filestorage;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@RestController
@RequestMapping("/attachments")
public class FileUploadController {
    private final FileStorageService fileStorageService;

    public FileUploadController(FileStorageService fileStorageService) {
        this.fileStorageService = fileStorageService;
    }

    @PostMapping("/upload-from-url")
    public ResponseEntity<String> uploadFromUrl(@RequestParam("requestUrl") String requestUrl) {
        try {
            // 解析用户输入的URL
            String processedUrl = fileStorageService.processUserUrl(requestUrl);
            // 下载远程文件
            String fileContent = fileStorageService.downloadRemoteFile(processedUrl);
            // 存储文件并返回响应
            String fileId = fileStorageService.storeFile(fileContent);
            return ResponseEntity.ok("{\\"fileId\\":\\"" + fileId + "\\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\\"error\\":\\"File upload failed\\"}");
        }
    }
}

class FileStorageService {
    // 处理用户提供的URL参数
    public String processUserUrl(String userInput) {
        // 添加协议头（用户输入可能包含特殊格式）
        if (userInput != null && !userInput.isEmpty()) {
            if (userInput.startsWith("http:")) {
                return "http:" + userInput;
            }
            return "https:" + userInput;
        }
        return userInput;
    }

    // 下载远程文件
    public String downloadRemoteFile(String targetUrl) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(targetUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                // 读取响应内容
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    // 存储文件逻辑（模拟）
    public String storeFile(String content) {
        // 生成唯一文件ID（模拟）
        return "file_" + System.currentTimeMillis();
    }
}