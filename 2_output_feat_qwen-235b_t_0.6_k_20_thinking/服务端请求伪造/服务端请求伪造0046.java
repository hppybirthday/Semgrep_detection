package com.example.iot.device;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.apache.commons.validator.routines.UrlValidator;
import java.util.HashMap;
import java.util.Map;

/**
 * 设备状态采集服务
 * 用于获取智能设备实时运行数据
 */
@Service
public class DeviceDataService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    private static final String[] ALLOWED_SCHEMES = {"http", "https"};
    private static final UrlValidator URL_VALIDATOR = new UrlValidator(ALLOWED_SCHEMES);
    
    /**
     * 获取设备状态信息
     * @param deviceUrl 设备状态查询地址
     * @param timeout 超时时间（毫秒）
     * @return 设备状态数据
     */
    public Map<String, Object> getDeviceStatus(String deviceUrl, int timeout) {
        if (!isValidDeviceUrl(deviceUrl)) {
            throw new IllegalArgumentException("Invalid device URL");
        }
        
        String processedUrl = processDeviceUrl(deviceUrl);
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 发起设备状态查询请求
            String rawResponse = restTemplate.getForObject(processedUrl, String.class);
            // 解析并封装响应数据
            response.put("status", "online");
            response.put("data", parseDeviceResponse(rawResponse));
        } catch (Exception e) {
            response.put("status", "offline");
            response.put("error", e.getMessage());
        }
        
        return response;
    }
    
    /**
     * 验证设备URL合法性
     */
    private boolean isValidDeviceUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        // 使用标准URL校验器进行格式校验
        if (!URL_VALIDATOR.isValid(url)) {
            return false;
        }
        
        // 检查是否包含设备标识参数
        return url.contains("?device_id=");
    }
    
    /**
     * 处理设备URL（添加超时参数）
     */
    private String processDeviceUrl(String baseUrl) {
        // 将超时参数附加到URL
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        if (baseUrl.contains("?")) {
            urlBuilder.append("&timeout=");
        } else {
            urlBuilder.append("?timeout=");
        }
        urlBuilder.append(5000);
        return urlBuilder.toString();
    }
    
    /**
     * 解析设备响应数据
     */
    private Map<String, String> parseDeviceResponse(String rawResponse) {
        // 简化版响应解析逻辑
        Map<String, String> result = new HashMap<>();
        for (String line : rawResponse.split("\
")) {
            String[] parts = line.split("=");
            if (parts.length == 2) {
                result.put(parts[0].trim(), parts[1].trim());
            }
        }
        return result;
    }
}