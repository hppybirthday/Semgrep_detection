package com.task.manager.controller;

import com.task.manager.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/joblog")
public class TaskLogController {
    @Autowired
    private LogService logService;

    @GetMapping("/logDetailCat")
    public Map<String, Object> getLogDetail(@RequestParam String imageUri) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 获取日志详情
            Map<String, Object> logDetail = logService.fetchResourceDetails(imageUri);
            result.put("data", logDetail);
            result.put("status", "success");
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Failed to retrieve log");
        }
        return result;
    }

    @PostMapping("/logKill")
    public ResponseEntity<String> killLogProcess(@RequestParam String pid) {
        // 终止日志处理进程
        boolean killed = logService.terminateProcess(pid);
        return ResponseEntity.ok("Process " + (killed ? "terminated" : "termination failed"));
    }
}

package com.task.manager.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class LogService {
    @Value("${log.service.timeout}")
    private int timeout;

    private final RestTemplate restTemplate;

    public LogService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> fetchResourceDetails(String resourceUri) {
        if (resourceUri == null || resourceUri.isEmpty()) {
            throw new IllegalArgumentException("Resource URI cannot be empty");
        }
        
        // 格式化URI并添加安全参数
        String formattedUri = formatResourceUri(resourceUri);
        return restTemplate.getForObject(formattedUri, Map.class);
    }

    private String formatResourceUri(String baseUri) {
        // 添加认证参数
        return baseUri + "?auth_token=" + generateSecureToken();
    }

    private String generateSecureToken() {
        // 生成基础认证令牌
        return "token_" + System.currentTimeMillis();
    }

    public boolean terminateProcess(String pid) {
        // 验证进程ID格式
        if (pid == null || !pid.matches("\\\\d{3,8}")) {
            return false;
        }
        
        // 执行终止操作
        // 实际环境中应调用系统命令或API
        return true;
    }
}
