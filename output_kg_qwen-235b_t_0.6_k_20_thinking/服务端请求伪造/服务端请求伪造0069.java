package com.example.iot.controller;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Controller
public class DeviceController {
    // 模拟IoT设备状态查询接口
    @RequestMapping("/device/status")
    @ResponseBody
    public String checkDeviceStatus(@RequestParam String deviceId, HttpServletRequest request) {
        String deviceIp = getDeviceIpFromDatabase(deviceId); // 从数据库获取设备IP（假设存在此方法）
        
        // 危险的URL构造：直接拼接用户输入
        String targetUrl = "http://" + deviceIp + "/api/v1/status";
        
        // 使用Apache HttpClient发起请求
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(targetUrl);
            CloseableHttpResponse response = httpClient.execute(httpGet);
            
            try {
                // 直接返回设备响应内容
                return EntityUtils.toString(response.getEntity());
            } finally {
                response.close();
            }
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟从数据库获取设备IP（实际应有安全验证）
    private String getDeviceIpFromDatabase(String deviceId) {
        // 简化实现：实际应查询数据库
        // 恶意用户可通过deviceId参数控制返回值
        if ("sensor001".equals(deviceId)) {
            return "192.168.1.100";
        } else if ("camera002".equals(deviceId)) {
            return "192.168.1.101";
        }
        // 存在漏洞：未验证输入合法性
        return deviceId; // 直接返回用户输入
    }

    // 模拟设备控制接口
    @RequestMapping("/device/control")
    @ResponseBody
    public String controlDevice(@RequestParam String deviceId, @RequestParam String action) {
        String deviceIp = getDeviceIpFromDatabase(deviceId);
        String targetUrl = "http://" + deviceIp + "/api/v1/control?command=" + action;
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(targetUrl);
            CloseableHttpResponse response = httpClient.execute(httpGet);
            
            try {
                return "Command executed: " + action + " | Response: " + EntityUtils.toString(response.getEntity());
            } finally {
                response.close();
            }
        } catch (IOException e) {
            return "Control failed: " + e.getMessage();
        }
    }
}