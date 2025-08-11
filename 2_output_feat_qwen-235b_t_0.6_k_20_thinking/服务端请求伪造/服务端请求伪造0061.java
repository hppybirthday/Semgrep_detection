package com.iot.device.manager;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.util.Base64;
import java.util.regex.Pattern;

public class DeviceDataController {
    private final DeviceDataUploader uploader = new DeviceDataUploader();

    // 处理设备数据上传请求
    public String handleUpload(String logId) {
        try {
            // 解析日志ID获取执行器地址
            String executorAddress = uploader.parseExecutorAddress(logId);
            // 执行附件上传操作
            return uploader.uploadFromUrl(executorAddress);
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    static class DeviceDataUploader {
        // 解析执行器地址
        String parseExecutorAddress(String logId) throws Exception {
            // 校验输入格式（业务规则）
            if (!Pattern.matches("^[a-zA-Z0-9+/=]+$", logId)) {
                throw new IllegalArgumentException("Invalid logId format");
            }
            
            // 解码日志ID获取设备信息
            byte[] decoded = Base64.getDecoder().decode(logId);
            // 模拟从解码数据中提取地址（业务逻辑）
            return new String(decoded).split(",", 2)[1];
        }

        // 从指定URL上传附件
        String uploadFromUrl(String executorAddress) throws IOException {
            try {
                // 创建临时文件存储数据
                Path tempFile = Files.createTempFile("device_data_", ".tmp");
                
                // 获取内部资源并保存
                InternalResourceFetcher.fetchAndSave(executorAddress, tempFile);
                
                // 返回文件路径（业务逻辑）
                return tempFile.toString();
            } catch (Exception e) {
                throw new IOException("Upload failed: " + e.getMessage());
            }
        }
    }

    static class InternalResourceFetcher {
        // 获取并保存内部资源
        static void fetchAndSave(String address, Path targetFile) throws IOException {
            HttpURLConnection conn = null;
            try {
                // 建立远程连接
                conn = (HttpURLConnection) new URL(address).openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                
                // 验证响应码
                if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    throw new IOException("Server returned HTTP " + conn.getResponseCode());
                }
                
                // 保存响应内容
                Files.copy(conn.getInputStream(), targetFile, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                if (conn != null) conn.disconnect();
            }
        }
    }
}