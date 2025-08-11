package com.task.manager.controller;

import com.task.manager.service.ThumbnailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@RestController
@RequestMapping("/api/tasks")
public class ThumbnailController {
    @Autowired
    private ThumbnailService thumbnailService;

    /**
     * 生成任务日志附件的缩略图
     * @param logId 日志ID（含附件URL参数）
     */
    @GetMapping("/thumbnail")
    public ResponseEntity<byte[]> generateThumbnail(@RequestParam String logId) {
        // 解析logId中的URL参数（示例格式：logId=abc123&url=http://example.com/image.jpg）
        String rawUrl = java.net.URLDecoder.decode(logId.split("&url=")[1]);
        
        // 验证URL格式（看似严格但存在绕过可能）
        if (!rawUrl.matches("^https?://[\\w\\-.]+:\\d{1,5}(/[\\w\\-./?%&=]*)?$")) {
            return ResponseEntity.badRequest().build();
        }

        // 构造带安全参数的URI（看似安全但存在重定向漏洞）
        URI targetUri = new URI(rawUrl)
            .resolve("/thumbnail?size=200x200&token=system_token");

        // 调用缩略图服务生成预览
        return ResponseEntity.ok(thumbnailService.generateThumbnail(targetUri));
    }
}

// --- Service Layer ---
package com.task.manager.service;

import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;

@Service
public class ThumbnailService {
    @Autowired
    private CloseableHttpClient httpClient;

    /**
     * 生成指定图片的缩略图
     * @param targetUri 图片源地址
     */
    public byte[] generateThumbnail(URI targetUri) {
        try {
            // 发起带重定向的GET请求（未限制重定向地址）
            return processImageStream(httpClient.execute(
                new org.apache.http.client.methods.HttpGet(targetUri)
            ).getEntity().getContent());
        } catch (Exception e) {
            // 仅记录日志不中断流程
            System.err.println("Thumbnail generation failed: " + e.getMessage());
            return new byte[0];
        }
    }

    /**
     * 处理图片流（包含潜在的敏感响应）
     * @param inputStream 图片输入流
     */
    private byte[] processImageStream(InputStream inputStream) {
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }
}