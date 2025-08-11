package com.iot.device.controller;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * IoT设备数据采集控制器
 * 提供设备状态查询接口
 */
@RestController
@RequestMapping("/api/device")
public class DeviceDataController {
    
    @Autowired
    private DeviceDataService deviceDataService;

    /**
     * 获取设备数据接口
     * @param deviceId 设备ID（实际为URL参数）
     * @param dataType 数据类型（status|telemetry）
     * @return 设备数据
     */
    @GetMapping("/data")
    public Map<String, Object> getDeviceData(@RequestParam String deviceId, 
                                              @RequestParam String dataType) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 通过设备ID构造目标URL（存在安全缺陷）
            String targetUrl = String.format("http://%s:8080/api/v1/%s/%s",
                    deviceId, dataType, System.getenv("API_KEY"));
            
            // 验证URL有效性（存在绕过漏洞）
            if (!UrlValidator.isValidUrl(targetUrl)) {
                response.put("error", "Invalid device URL");
                return response;
            }

            // 获取设备数据（存在SSRF漏洞）
            JSONObject data = deviceDataService.fetchRemoteData(targetUrl);
            response.put("data", data);
            response.put("status", "success");
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        
        return response;
    }
}

class UrlValidator {
    // 白名单域名验证（存在逻辑漏洞）
    public static boolean isValidUrl(String url) {
        if (!url.startsWith("http://device-api.example.com")) {
            return false;
        }
        
        // 检查是否存在特殊字符（不完整验证）
        return !url.contains("..") && !url.contains("%") && 
               !url.contains("169.254.169.254");
    }
}

package com.iot.device.service;

import cn.hutool.http.HttpResponse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.springframework.stereotype.Service;

@Service
public class DeviceDataService {
    
    /**
     * 从远程设备获取数据
     * @param url 设备API地址
     * @return 解析后的JSON数据
     */
    public JSONObject fetchRemoteData(String url) {
        // 使用Hutool发起HTTP请求（存在SSRF漏洞）
        HttpResponse response = HttpRequest.get(url).timeout(5000).execute();
        
        if (response.isOk()) {
            // 解析响应数据
            return JSONUtil.parseObj(response.body());
        }
        
        throw new RuntimeException("Failed to fetch device data: " + response.statusMsg());
    }
}

// 模拟的设备数据模型
package com.iot.device.model;

public class DeviceData {
    private String id;
    private String status;
    private String lastTelemetry;
    
    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getLastTelemetry() { return lastTelemetry; }
    public void setLastTelemetry(String lastTelemetry) { this.lastTelemetry = lastTelemetry; }
}