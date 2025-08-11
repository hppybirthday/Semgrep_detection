package com.crm.thumbnail;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ThumbnailReconciler {
    
    // 模拟日志记录组件
    private Map<String, String> jobLogs = new HashMap<>();
    
    public ThumbnailReconciler() {
        // 初始化测试数据
        jobLogs.put("1001", "Thumbnail generation started");
        jobLogs.put("1002", "Image optimization completed");
    }

    @GetMapping("/joblog/logDetailCat")
    public String getLogDetailCat(@RequestParam String permalink) {
        return processRequest(permalink);
    }

    @GetMapping("/joblog/logKill")
    public String killLogProcess(@RequestParam String permalink) {
        return processRequest(permalink);
    }

    private String processRequest(String targetUrl) {
        StringBuilder response = new StringBuilder();
        
        try {
            // 存在漏洞的URL请求发起
            URL url = new URL(targetUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // 模拟请求头设置
            connection.setRequestProperty("User-Agent", "ThumbnailReconciler/1.0");
            connection.setInstanceFollowRedirects(true); // 允许重定向
            
            // 读取响应
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
        } catch (IOException e) {
            response.append("{\\"error\\":\\"").append(e.getMessage()).append("\\"}");
        }
        
        return response.toString();
    }

    // 模拟内部日志查询方法
    private String getInternalLog(String jobId) {
        return jobLogs.getOrDefault(jobId, "Log not found");
    }
}