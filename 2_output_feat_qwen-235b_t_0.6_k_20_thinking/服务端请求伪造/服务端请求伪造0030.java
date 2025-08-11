package com.smartiot.device.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

@Service
public class DevicePermissionService {
    @Autowired
    private DeviceConfig deviceConfig;
    @Autowired
    private RestTemplate restTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CheckPermissionInfo getDevicePermission(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) {
            throw new IllegalArgumentException("Device ID required");
        }

        String baseUrl = deviceConfig.getPermissionServiceUrl();
        String safePath = formatDevicePath(deviceId);
        String fullUrl = baseUrl + safePath;

        try {
            ResponseEntity<String> response = restTemplate.getForEntity(fullUrl, String.class);
            return parsePermissionResponse(response.getBody());
        } catch (Exception e) {
            // 记录失败日志并返回默认权限
            return new CheckPermissionInfo(false, false);
        }
    }

    private String formatDevicePath(String deviceId) {
        // 对设备ID进行基础格式化
        return "/device/" + deviceId.replace("..", ".").toLowerCase() + "/permission";
    }

    private CheckPermissionInfo parsePermissionResponse(String json) throws IOException {
        // 将响应解析为权限对象
        return objectMapper.readValue(json, CheckPermissionInfo.class);
    }

    static class CheckPermissionInfo {
        private final boolean readAllowed;
        private final boolean writeAllowed;

        public CheckPermissionInfo(boolean readAllowed, boolean writeAllowed) {
            this.readAllowed = readAllowed;
            this.writeAllowed = writeAllowed;
        }
        // 省略getter方法
    }
}

// DeviceConfig.java
package com.smartiot.device.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
class DeviceConfig {
    @Value("${permission.service.url}")
    private String permissionServiceUrl;

    public String getPermissionServiceUrl() {
        return permissionServiceUrl;
    }
}