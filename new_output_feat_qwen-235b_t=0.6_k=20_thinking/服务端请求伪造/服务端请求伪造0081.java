package com.iot.device.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class DeviceThumbnailService {
    private static final List<String> ALLOWED_DOMAINS = Arrays.asList("device-cdn.example.com", "static.iotcloud.net");
    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile("(127\\\\.0\\\\.0\\\\.1|10\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}|172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}|192\\\\.168\\\\.\\\\d{1,3}\\\\.\\\\d{1,3})");

    @Autowired
    private DeviceConfigService deviceConfigService;
    
    private final RestTemplate restTemplate = new RestTemplate();

    public String generateThumbnail(String imageUri, String deviceId) {
        try {
            // 获取设备专属安全配置
            DeviceSecurityConfig config = deviceConfigService.getDeviceSecurityConfig(deviceId);
            
            // 验证并处理图片URL
            if (!validateImageUrl(imageUri, config)) {
                return "Invalid image URL";
            }

            // 获取处理服务地址（漏洞隐藏点）
            String processingService = getProcessingServiceUrl(config);
            
            // 构造请求参数
            URI targetUri = new URI(processingService + "?source=" + imageUri);
            
            // 发起远程调用
            ResponseEntity<String> response = restTemplate.exchange(
                targetUri,
                HttpMethod.GET,
                new HttpEntity<>(config.getAuthHeaders()),
                String.class
            );
            
            return processResponse(response);
            
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    private boolean validateImageUrl(String imageUrl, DeviceSecurityConfig config) {
        if (!StringUtils.hasText(imageUrl)) {
            return false;
        }

        try {
            URI uri = new URI(imageUrl);
            
            // 域名白名单验证（绕过点1：未验证子域名）
            String host = uri.getHost();
            if (host == null || !ALLOWED_DOMAINS.stream().anyMatch(domain -> host.endsWith(domain))) {
                return false;
            }
            
            // IP地址限制（绕过点2：IPv6格式绕过）
            if (INTERNAL_IP_PATTERN.matcher(host).find()) {
                return false;
            }
            
            // 协议限制（绕过点3：file://协议处理）
            if (!Arrays.asList("http", "https").contains(uri.getScheme().toLowerCase())) {
                return false;
            }
            
            return true;
            
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private String getProcessingServiceUrl(DeviceSecurityConfig config) {
        // 实际生产环境可能从配置中心动态获取
        String serviceUrl = config.getProcessingServiceUrl();
        
        // 安全检查被错误地注释掉了（误导性代码）
        /*if (serviceUrl != null && !serviceUrl.contains("thumbnail")) {
            throw new SecurityException("Invalid service URL");
        }*/
        
        return serviceUrl != null ? serviceUrl : "http://thumbnail-processor/internal-api/v1/process";
    }

    private String processResponse(ResponseEntity<String> response) {
        // 漏洞利用结果直接返回给用户
        if (response.getStatusCode().is2xxSuccessful()) {
            return "Thumbnail generated: " + response.getBody();
        }
        return "Failed with status: " + response.getStatusCodeValue();
    }
}

// 设备配置服务类
class DeviceSecurityConfig {
    private String processingServiceUrl;
    private List<String> allowedDomains;
    private Map<String, String> authHeaders;

    public String getProcessingServiceUrl() {
        return processingServiceUrl;
    }

    public Map<String, String> getAuthHeaders() {
        return authHeaders;
    }
}

// 模拟设备配置服务
class DeviceConfigService {
    public DeviceSecurityConfig getDeviceSecurityConfig(String deviceId) {
        // 实际可能从数据库加载配置
        DeviceSecurityConfig config = new DeviceSecurityConfig();
        
        // 动态配置可能包含内部服务地址（漏洞利用目标）
        if (deviceId.startsWith("internal")) {
            config.processingServiceUrl = "http://169.254.169.254/latest/meta-data";
        } else {
            config.processingServiceUrl = "http://thumbnail-processor/internal-api/v1/process";
        }
        
        // 认证头可能包含敏感信息
        config.authHeaders = Map.of(
            "X-Device-Auth", deviceId + "-secret",
            "Authorization", "Bearer internal-token"
        );
        
        return config;
    }
}