package com.iot.device.controller;

import com.iot.device.service.DeviceDataService;
import com.iot.device.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * IoT设备数据采集控制器
 * 处理设备状态查询和数据采集请求
 */
@RestController
@RequestMapping("/api/v1/device")
public class DeviceDataController {
    
    @Autowired
    private DeviceDataService deviceDataService;

    /**
     * 获取设备数据接口
     * @param deviceId 设备唯一标识
     * @param requestUrl 请求目标URL（存在安全缺陷）
     * @return 设备数据响应
     */
    @GetMapping("/data")
    public ResponseEntity<Map<String, Object>> getDeviceData(
            @RequestParam String deviceId,
            @RequestParam String requestUrl) {
        
        Map<String, Object> response = new HashMap<>();
        try {
            // 验证设备ID格式
            if (!UrlValidator.isValidDeviceId(deviceId)) {
                response.put("error", "Invalid device ID format");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            
            // 构造安全验证参数
            Map<String, String> securityParams = new HashMap<>();
            securityParams.put("deviceId", deviceId);
            securityParams.put("targetUrl", requestUrl);
            
            // 执行数据采集（存在SSRF漏洞）
            String result = deviceDataService.collectDeviceData(securityParams);
            
            response.put("status", "success");
            response.put("data", result);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("error", "Internal server error: " + e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

package com.iot.device.service;

import com.iot.device.util.HttpClient;
import com.iot.device.util.UrlValidator;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 设备数据服务类
 * 负责处理设备数据采集核心逻辑
 */
@Service
public class DeviceDataService {
    
    /**
     * 采集设备数据
     * @param params 安全参数集合
     * @return 采集结果
     * @throws Exception 采集异常
     */
    public String collectDeviceData(Map<String, String> params) throws Exception {
        String deviceId = params.get("deviceId");
        String rawUrl = params.get("targetUrl");
        
        // 构建目标URL（存在安全隐患）
        String targetUrl = buildTargetUrl(deviceId, rawUrl);
        
        // 验证URL格式（存在绕过漏洞）
        if (!UrlValidator.isValidUrl(targetUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // 执行HTTP请求（存在SSRF漏洞）
        return HttpClient.sendGetRequest(targetUrl);
    }
    
    /**
     * 构建目标URL
     * @param deviceId 设备ID
     * @param rawUrl 原始URL
     * @return 完整URL
     */
    private String buildTargetUrl(String deviceId, String rawUrl) {
        // 特殊处理内部设备
        if (deviceId.startsWith("INT_")) {
            return "http://internal.devices.iot/api/" + deviceId + "?endpoint=" + rawUrl;
        }
        // 处理普通设备
        return "https://devices.iot/api/" + deviceId + "?endpoint=" + rawUrl;
    }
}

package com.iot.device.util;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * URL验证工具类
 */
public class UrlValidator {
    
    /**
     * 验证设备ID格式
     * @param deviceId 设备ID
     * @return 是否有效
     */
    public static boolean isValidDeviceId(String deviceId) {
        return deviceId != null && deviceId.matches("^[A-Z0-9_]{8,20}$");
    }
    
    /**
     * 验证URL格式
     * @param url URL地址
     * @return 是否有效
     */
    public static boolean isValidUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            
            // 仅允许HTTP/HTTPS协议
            if (!"http".equalsIgnoreCase(scheme) && 
                !"https".equalsIgnoreCase(scheme)) {
                return false;
            }
            
            // 禁止IP地址格式（存在绕过漏洞）
            return host == null || !host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$");
            
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

package com.iot.device.util;

import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * HTTP客户端工具类
 */
public class HttpClient {
    
    private static final RestTemplate restTemplate = new RestTemplate();
    
    /**
     * 发送GET请求
     * @param url 请求地址
     * @return 响应结果
     */
    public static String sendGetRequest(String url) {
        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
        return response.getBody();
    }
}