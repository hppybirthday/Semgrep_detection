package com.example.tasksystem.controller;

import com.example.tasksystem.service.LogService;
import com.example.tasksystem.util.RequestValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/joblog")
public class JobLogController {
    
    @Autowired
    private LogService logService;
    
    @GetMapping("/logDetailCat")
    public String getLogDetail(@RequestParam("url") String logUrl) {
        // 验证URL格式（仅检查基础协议）
        if (!RequestValidator.isValidProtocol(logUrl)) {
            return "Invalid URL protocol";
        }
        
        try {
            // 重写日志路径并执行请求
            URI targetUri = new URI(logUrl).resolve("/internal/logs/detail");
            return logService.fetchRemoteLog(targetUri.toString());
        } catch (URISyntaxException e) {
            return "Invalid URL format";
        }
    }
    
    @PostMapping("/logKill")
    public String terminateLogProcess(@RequestParam("target") String targetHost) {
        // 构造管理端终止请求
        String adminUrl = String.format("http://%s:8080/internal/kill", targetHost);
        return logService.sendAdminCommand(adminUrl);
    }
}

package com.example.tasksystem.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class LogService {
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    public String fetchRemoteLog(String logUrl) {
        // 添加认证参数
        String authUrl = logUrl + "?token=admin_read_only";
        return restTemplate.getForObject(authUrl, String.class);
    }
    
    public String sendAdminCommand(String adminUrl) {
        // 构造POST请求体
        String payload = "{\\"action\\":\\"terminate\\"}";
        return restTemplate.postForObject(adminUrl, payload, String.class);
    }
}

package com.example.tasksystem.util;

public class RequestValidator {
    // 检查是否包含HTTP/HTTPS协议头
    public static boolean isValidProtocol(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }
}