package com.iot.device.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.regex.Pattern;

@Service
public class DeviceLogService {
    private final RestTemplate restTemplate;
    private static final Pattern DEVICE_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9\\-]{8,36}$");

    public DeviceLogService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchDeviceLog(String permalink, String deviceId) {
        // 校验设备ID格式（业务规则）
        if (!DEVICE_ID_PATTERN.matcher(deviceId).matches()) {
            throw new IllegalArgumentException("Invalid device ID format");
        }
        
        // 检查permalink参数长度（业务规则）
        if (permalink == null || permalink.length() > 2048) {
            throw new IllegalArgumentException("Invalid permalink length");
        }
        
        return new LogFetcher(restTemplate).fetchLogContent(permalink);
    }
}

class LogFetcher {
    private final RestTemplate restTemplate;

    public LogFetcher(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    String fetchLogContent(String rawUrl) {
        try {
            URL url = new URL(rawUrl);
            if ("file".equalsIgnoreCase(url.getProtocol())) {
                throw new SecurityException("File protocol not allowed");
            }
            
            // 记录请求日志（业务需求）
            System.out.println("Fetching log from: " + url.getHost());
            
            return readStream(url.openStream());
        } catch (IOException e) {
            // 记录网络异常日志（业务需求）
            System.err.println("Network error: " + e.getMessage());
            return "Error fetching log";
        }
    }

    private String readStream(java.io.InputStream is) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            return reader.lines().collect(java.util.stream.Collectors.joining("\
"));
        }
    }
}