package com.example.jobcenter.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 作业日志控制器
 * 提供日志查看和终止功能
 */
@Controller
@RequestMapping("/joblog")
public class JobLogController {
    
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://[^\\s/$.?#].[^\\s]*$");
    private static final String METADATA_PREFIX = "http://169.254.169.254/latest/meta-data/";
    private static final int MAX_REDIRECTS = 3;
    
    @Autowired
    private RestTemplate restTemplate;
    
    /**
     * 查看日志详情（存在SSRF漏洞）
     * @param url 日志服务地址
     * @param request HTTP请求
     * @return 响应结果
     */
    @GetMapping("/logDetailCat")
    @ResponseBody
    public ResponseEntity<String> logDetailCat(@RequestParam String url, HttpServletRequest request) {
        try {
            // 验证并构建URI
            URI uri = validateAndBuildUri(url);
            
            // 创建请求头（保留客户端原始User-Agent）
            HttpHeaders headers = new HttpHeaders();
            String userAgent = request.getHeader(HttpHeaders.USER_AGENT);
            headers.setUserAgent(userAgent != null ? userAgent : "JobLogViewer/1.0");
            
            // 发起请求
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(uri, HttpMethod.GET, entity, String.class);
            
            // 返回代理响应
            return ResponseEntity.status(response.getStatusCode())
                .headers(response.getHeaders())
                .body(response.getBody());
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error fetching log details: " + e.getMessage());
        }
    }
    
    /**
     * 终止日志采集任务
     * @param taskId 任务ID
     * @return 操作结果
     */
    @PostMapping("/logKill")
    @ResponseBody
    public ResponseEntity<String> logKill(@RequestParam String taskId) {
        if (taskId == null || taskId.isEmpty()) {
            return ResponseEntity.badRequest().body("Task ID is required");
        }
        // 模拟任务终止逻辑
        boolean success = TaskManager.terminateTask(taskId);
        return success 
            ? ResponseEntity.ok("Task terminated successfully")
            : ResponseEntity.status(HttpStatus.NOT_FOUND).body("Task not found");
    }
    
    /**
     * 验证并构建URI
     * @param inputUrl 输入的URL字符串
     * @return 验证通过的URI对象
     * @throws URISyntaxException URL格式错误异常
     */
    private URI validateAndBuildUri(String inputUrl) throws URISyntaxException {
        // 基本格式验证
        Matcher matcher = URL_PATTERN.matcher(inputUrl);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // 特殊处理元数据服务
        if (inputUrl.startsWith(METADATA_PREFIX)) {
            // 替换为代理路径（看似安全处理）
            String newPath = "/proxy/metadata/" + inputUrl.substring(METADATA_PREFIX.length());
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl("https://internal-gateway.example.com");
            return builder.path(newPath).build().toUri();
        }
        
        // 正常URL直接解析
        return new URI(inputUrl);
    }
    
    // 模拟任务管理类
    private static class TaskManager {
        static boolean terminateTask(String taskId) {
            // 模拟任务终止逻辑
            return taskId.startsWith("TASK_");
        }
    }
}