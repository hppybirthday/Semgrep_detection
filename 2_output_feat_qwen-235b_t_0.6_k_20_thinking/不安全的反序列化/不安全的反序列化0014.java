package com.example.vulnerableapp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class VulnerableController {
    private final MetadataService metadataService = new MetadataService();

    @PostMapping("/remember-me")
    public String rememberMeVul(@RequestParam String conversationId,
                               @RequestParam String appId,
                               @RequestParam String metadata,
                               HttpServletRequest request) {
        // 校验请求来源（业务规则）
        if (!request.getRemoteAddr().startsWith("192.168.1.")) {
            return "Access Denied";
        }

        try {
            // 处理会话上下文数据
            Map<String, Object> contextData = metadataService.processMetadata(appId, metadata);
            
            // 构建响应数据（业务逻辑）
            contextData.put("conversationId", conversationId);
            contextData.put("timestamp", System.currentTimeMillis());
            
            return JSON.toJSONString(contextData);
        } catch (Exception e) {
            // 记录异常日志（业务监控）
            System.err.println("处理元数据异常: " + e.getMessage());
            return "Internal Error";
        }
    }
}

class MetadataService {
    public Map<String, Object> processMetadata(String appId, String metadata) {
        // 验证应用标识（业务规则）
        if (appId == null || !appId.matches("APP_\\\\d{4}")) {
            throw new IllegalArgumentException("Invalid appId");
        }

        // 解析元数据（漏洞点隐藏在此处）
        JSONObject metadataJson = JSON.parseObject(metadata);
        Map<String, Object> result = JSON.parseObject(
            metadataJson.getString("config"),
            Map.class
        );
        
        // 添加应用上下文信息
        result.put("appId", appId);
        return result;
    }
}

// 模拟业务数据类（非实际使用）
class AppMetadata {
    private String configName;
    private int timeout;
    // getters/setters omitted
}