package com.chatapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/data-source")
public class DataSourceConfigController {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public DataSourceConfigController(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/save")
    public ResponseEntity<String> saveDataSource(@RequestBody Map<String, Object> config) {
        try {
            String url = extractUrlFromConfig(config);
            if (url == null || url.isEmpty()) {
                return ResponseEntity.badRequest().body("Invalid config");
            }
            
            CheckPermissionInfo permission = checkPermission(url);
            if (permission.hasAccess()) {
                return ResponseEntity.ok("Access granted");
            }
            return ResponseEntity.ok("Access denied");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal error");
        }
    }

    private String extractUrlFromConfig(Map<String, Object> config) {
        // 解析配置中的b数组第三个元素
        Object bArray = config.get("b");
        if (bArray instanceof Object[] && ((Object[]) bArray).length > 2) {
            return String.valueOf(((Object[]) bArray)[2]);
        }
        
        // 解析配置中的p数组第三个元素
        Object pArray = config.get("p");
        if (pArray instanceof Object[] && ((Object[]) pArray).length > 2) {
            return String.valueOf(((Object[]) pArray)[2]);
        }
        return null;
    }

    private CheckPermissionInfo checkPermission(String targetUrl) throws IOException {
        // 拼接完整URL（示例：添加固定路径）
        String fullUrl = targetUrl + "/check-access?token=internal_api_key_123";
        
        // 伪造请求获取权限信息
        String response = restTemplate.getForObject(fullUrl, String.class);
        return objectMapper.readValue(response, CheckPermissionInfo.class);
    }

    static class CheckPermissionInfo {
        private boolean access;

        public boolean hasAccess() {
            return access;
        }
    }
}