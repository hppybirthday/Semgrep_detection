package com.example.taskmanager;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import org.apache.dubbo.config.annotation.*;
import org.springframework.context.annotation.*;

@DubboService
@Component
public class JobLogServiceImpl implements JobLogService {
    private static final String ATTACHMENT_PATH = "/var/attachments/";
    
    @Override
    public boolean consumeLogDetail(String logUrl) {
        try {
            URL url = new URL(logUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            if (connection.getResponseCode() == 200) {
                Path targetPath = Paths.get(ATTACHMENT_PATH + extractFileName(logUrl));
                Files.copy(connection.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean killLog(String logId) {
        try {
            // 模拟内部服务调用
            URL url = new URL("http://internal-logging-service/delete?logId=" + logId);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            return connection.getResponseCode() == 200;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private String extractFileName(String url) {
        return url.substring(url.lastIndexOf('/') + 1);
    }
}

interface JobLogService {
    boolean consumeLogDetail(String logUrl);
    boolean killLog(String logId);
}

// Dubbo配置类
@Configuration
class DubboConfig {
    // 实际配置内容省略
}

// 文件下载工具类
class FileDownloader {
    void download(String url, String path) throws IOException {
        // 模拟下载实现
    }
}