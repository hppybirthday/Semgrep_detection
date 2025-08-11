package com.example.filecenter.controller;

import com.example.filecenter.service.AttachmentService;
import com.example.filecenter.vo.AttachmentUploadRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/attachments")
public class FileUploadController {
    @Autowired
    private AttachmentService attachmentService;

    @PostMapping("/upload-from-url")
    public ResponseEntity<String> uploadFromUrl(@RequestBody AttachmentUploadRequest request) {
        try {
            // 解析JSON参数中的URL路径
            List<String> urls = request.getUrls();
            if (urls == null || urls.size() < 3) {
                return ResponseEntity.badRequest().body("Invalid URL list");
            }
            
            // 获取第三个元素作为目标地址（业务规则）
            String targetUrl = urls.get(2);
            
            // 执行文件下载与存储
            String result = attachmentService.processRemoteFile(targetUrl);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}