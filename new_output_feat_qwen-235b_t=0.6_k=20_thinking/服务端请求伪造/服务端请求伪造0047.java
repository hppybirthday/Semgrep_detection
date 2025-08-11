package com.example.jobcenter.controller;

import com.example.jobcenter.service.JobLogService;
import com.example.jobcenter.util.UrlParserUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/joblog")
public class JobLogController {
    @Autowired
    private JobLogService jobLogService;

    @GetMapping("/logDetailCat")
    public void catLogDetail(@RequestParam("jobId") String jobId,
                             @RequestParam("service") String service,
                             HttpServletResponse response) throws IOException {
        try {
            String result = jobLogService.getLogContent(jobId, service);
            response.getWriter().write(result);
        } catch (Exception e) {
            response.sendError(500, "Internal Server Error");
        }
    }

    @GetMapping("/logKill")
    public Map<String, Object> killLogProcess(@RequestParam("jobId") String jobId,
                                              @RequestParam("service") String service) {
        Map<String, Object> result = new HashMap<>();
        try {
            boolean success = jobLogService.terminateProcess(jobId, service);
            result.put("status", success ? "success" : "failed");
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", e.getMessage());
        }
        return result;
    }
}

package com.example.jobcenter.service;

import com.example.jobcenter.util.UrlParserUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class JobLogService {
    private final RestTemplate restTemplate;
    private final UrlParserUtil urlParserUtil;

    @Value("${jobcenter.api.timeout}")
    private int timeout;

    public JobLogService(RestTemplate restTemplate, UrlParserUtil urlParserUtil) {
        this.restTemplate = restTemplate;
        this.urlParserUtil = urlParserUtil;
    }

    public String getLogContent(String jobId, String service) {
        String apiUrl = urlParserUtil.parse(service, "logcat", jobId);
        return restTemplate.getForObject(apiUrl, String.class);
    }

    public boolean terminateProcess(String jobId, String service) {
        String apiUrl = urlParserUtil.parse(service, "logkill", jobId);
        Map<String, Object> response = restTemplate.postForObject(apiUrl, null, Map.class);
        return response != null && "OK".equals(response.get("status"));
    }
}

package com.example.jobcenter.util;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class UrlParserUtil {
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    public String parse(String service, String action, String jobId) {
        // 漏洞点：未正确验证service参数，允许构造任意URL
        String baseUrl = "https://" + service + "/api/v1/job/" + action + "?id=" + jobId;
        if (baseUrl.contains("..")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return validateUrl(baseUrl);
    }

    private String validateUrl(String url) {
        // 有缺陷的验证逻辑：仅阻止包含IP地址的URL，但存在绕过可能
        if (IP_PATTERN.matcher(url).find()) {
            if (!url.contains("192.168.1.")) {
                throw new IllegalArgumentException("Internal IP access denied");
            }
        }
        return url;
    }
}

// application.properties配置示例
// jobcenter.api.timeout=5000
// spring.mvc.async.request-timeout=0