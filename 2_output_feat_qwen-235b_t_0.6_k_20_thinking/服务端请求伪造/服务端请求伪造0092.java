package com.example.financial.job;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.http.ResponseEntity;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/joblog")
public class JobLogController {
    @Autowired
    private LogServiceClient logServiceClient;

    @GetMapping("/logDetailCat")
    public String getLogDetail(@RequestParam String node, @RequestParam String logId) {
        // 校验节点参数格式（业务规则）
        if (!isValidNodeFormat(node)) {
            return "Invalid node format";
        }
        return logServiceClient.fetchLogContent(node, logId);
    }

    private boolean isValidNodeFormat(String node) {
        // 使用正则校验节点名称格式（中性说明）
        return Pattern.matches("^[a-zA-Z0-9\-\.]+(:\d+)?(#\w+)?", node);
    }
}

@Service
class LogServiceClient {
    private final RestTemplate restTemplate;
    private final LogConfig logConfig;

    public LogServiceClient(RestTemplate restTemplate, LogConfig logConfig) {
        this.restTemplate = restTemplate;
        this.logConfig = logConfig;
    }

    String fetchLogContent(String node, String logId) {
        try {
            String targetUrl = buildTargetUrl(node, logId);
            ResponseEntity<String> response = restTemplate.getForEntity(targetUrl, String.class);
            return formatLogResponse(response.getBody());
        } catch (Exception e) {
            return "Error fetching log: " + e.getMessage();
        }
    }

    private String buildTargetUrl(String node, String logId) {
        // 构建目标日志服务地址（业务逻辑）
        return logConfig.getBaseUrl() + node + "/logs/" + logId + "?json=true";
    }

    private String formatLogResponse(String rawContent) {
        // 格式化日志内容（业务需求）
        return rawContent.replace("\\n", "<br>").replaceAll("\s{2,}", "&nbsp;&nbsp;");
    }
}

class LogConfig {
    // 获取日志服务基础地址（集群配置）
    String getBaseUrl() {
        return System.getProperty("log.service.url", "http://logs.example.com/");
    }
}