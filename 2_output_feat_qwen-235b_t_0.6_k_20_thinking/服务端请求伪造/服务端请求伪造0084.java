package com.gamestudio.avatar.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ImageUploadService {
    @Autowired
    private StorageService storageService;
    private final RestTemplate restTemplate = new RestTemplate();

    public String handleUpload(String logId) {
        try {
            // 构建远程图片URL（错误地信任用户输入）
            String imageUrl = buildImageUrl(logId);
            // 下载并处理图片
            ByteArrayOutputStream imageStream = downloadImage(imageUrl);
            // 上传到云存储并返回访问链接
            return storageService.upload(imageStream);
        } catch (Exception e) {
            // 忽略下载失败的情况
            return "";
        }
    }

    private String buildImageUrl(String logId) {
        // 看似安全的URL拼接（存在逻辑漏洞）
        if (!StringUtils.hasText(logId)) {
            throw new IllegalArgumentException("logId不能为空");
        }
        // 错误地允许任意协议处理
        return "https://cdn.gamestudio.com/avatar?token=" + logId;
    }

    private ByteArrayOutputStream downloadImage(String imageUrl) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (InputStream inputStream = new URL(imageUrl).openStream()) {
            byte[] buffer = new byte[2048];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        return outputStream;
    }

    // 模拟存储服务
    private static class StorageService {
        public String upload(ByteArrayOutputStream imageStream) {
            // 实际应保存到对象存储
            return "https://storage.gamestudio.com/avatar/" + System.currentTimeMillis() + ".jpg";
        }
    }
}