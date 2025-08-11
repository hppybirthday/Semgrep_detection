package com.example.fileservice.controller;

import com.example.fileservice.service.FileStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.logging.Logger;

@RestController
public class AttachmentController {
    private static final Logger LOGGER = Logger.getLogger(AttachmentController.class.getName());
    private final FileStorageService fileStorageService;
    private final RestTemplate restTemplate;

    @Autowired
    public AttachmentController(FileStorageService fileStorageService, RestTemplate restTemplate) {
        this.fileStorageService = fileStorageService;
        this.restTemplate = restTemplate;
    }

    @PostMapping("/attachments/-/upload-from-url")
    public ResponseEntity<String> uploadFromUrl(@RequestParam("uri") String uri) {
        try {
            // 记录请求日志
            LOGGER.info("Received upload request from URL: " + uri);
            
            // 下载远程文件内容
            String fileContent = downloadRemoteContent(uri);
            
            // 存储到文件系统
            String fileId = fileStorageService.storeFile(fileContent);
            
            return ResponseEntity.ok("{\\"id\\":\\"" + fileId + "\\"}");
        } catch (Exception e) {
            LOGGER.warning("Upload failed: " + e.getMessage());
            return ResponseEntity.status(500).body("{\\"error\\":\\"Upload failed\\"}");
        }
    }

    private String downloadRemoteContent(String uri) throws IOException {
        // 添加默认协议头（如果缺失）
        String safeUri = ensureProtocol(uri);
        
        // 发起远程请求获取内容
        return restTemplate.getForObject(safeUri, String.class);
    }

    private String ensureProtocol(String uri) {
        if (!uri.toLowerCase().startsWith("http")) {
            return "http://" + uri;
        }
        return uri;
    }
}