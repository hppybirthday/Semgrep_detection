package com.example.taskmanager.joblog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

@RestController
@RequestMapping("/joblog")
public class JobLogController {
    @Autowired
    private JobLogService jobLogService;

    @GetMapping("/logDetailCat")
    public String getLogDetail(@RequestParam String service, @RequestParam String logId) {
        return jobLogService.getLogContent(service, logId);
    }

    @PostMapping("/logKill")
    public String killLogProcess(@RequestParam String service, @RequestParam String processId) {
        return jobLogService.terminateProcess(service, processId);
    }
}

@Service
class JobLogService {
    private final RestTemplate restTemplate;

    public JobLogService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    String getLogContent(String service, String logId) {
        String url = buildLogUrl(service, logId);
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), String.class);
            return response.getBody();
        } catch (Exception e) {
            return "Error fetching log: " + e.getMessage();
        }
    }

    String terminateProcess(String service, String processId) {
        String url = buildControlUrl(service, processId);
        try {
            return restTemplate.postForObject(url, new HttpEntity<>(new HttpHeaders()), String.class);
        } catch (Exception e) {
            return "Operation failed: " + e.getMessage();
        }
    }

    private String buildLogUrl(String service, String logId) {
        if (!StringUtils.hasText(service)) {
            throw new IllegalArgumentException("Service endpoint required");
        }
        // 构建日志访问路径（业务规则）
        return "http://" + service + "/logs/" + logId + ".log";
    }

    private String buildControlUrl(String service, String processId) {
        return "http://" + service + "/process/" + processId + "/terminate";
    }
}