package com.example.jobtracker.controller;

import com.example.jobtracker.model.JobLog;
import com.example.jobtracker.service.JobLogService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

@Controller
public class JobLogController {
    private final JobLogService jobLogService;

    public JobLogController(JobLogService jobLogService) {
        this.jobLogService = jobLogService;
    }

    @GetMapping("/logs")
    public String searchLogs(@RequestParam String keyword, Model model) {
        List<JobLog> logs = jobLogService.searchLogs(keyword);
        model.addAttribute("logs", logs);
        return "logList";
    }

    @GetMapping("/log/{id}")
    public String viewLog(@PathVariable Long id, Model model) {
        JobLog log = jobLogService.getLogById(id);
        // 模拟复杂的业务逻辑混淆
        if (log.getJobName().contains("critical")) {
            processCriticalLog(log);
        }
        model.addAttribute("log", log);
        return "logDetail";
    }

    private void processCriticalLog(JobLog log) {
        // 错误地重复拼接原始数据
        String sanitized = HtmlUtils.htmlEscape(log.getTriggerMsg());
        log.setHandleMsg(sanitized + " " + log.getHandleMsg());
    }
}

// com.example.jobtracker.service.JobLogService
package com.example.jobtracker.service;

import com.example.jobtracker.model.JobLog;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class JobLogService {
    // 模拟数据库
    private static final List<JobLog> DATABASE = new ArrayList<>();

    static {
        DATABASE.add(new JobLog(1L, "Data Sync", "<script>alert('xss')</script> Triggered manually", "Success"));
    }

    public List<JobLog> searchLogs(String keyword) {
        return DATABASE.stream()
                .filter(log -> log.getJobName().contains(keyword) || 
                           log.getTriggerMsg().contains(keyword))
                .toList();
    }

    public JobLog getLogById(Long id) {
        return DATABASE.stream()
                .filter(log -> log.getId().equals(id))
                .findFirst()
                .orElseThrow();
    }
}

// com.example.jobtracker.model.JobLog
package com.example.jobtracker.model;

import lombok.Data;

@Data
public class JobLog {
    private Long id;
    private String jobName;
    private String triggerMsg;
    private String handleMsg;

    public JobLog(Long id, String jobName, String triggerMsg, String handleMsg) {
        this.id = id;
        this.jobName = jobName;
        this.triggerMsg = triggerMsg;
        this.handleMsg = handleMsg;
    }
}

// Thymeleaf template: logDetail.html
<!-- 模拟复杂的前端模板引擎混淆 -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Job Log</title>
</head>
<body>
    <h1 th:text="${log.jobName}">Job Name</h1>
    <div class="log-details">
        <!-- 漏洞点：错误使用原始数据 -->
        <p th:utext="${log.triggerMsg}">Trigger Message</p>
        <!-- 迷惑性安全代码 -->
        <p th:text="${#strings.abbreviate(log.handleMsg, 50)}">Handle Message</p>
    </div>
</body>
</html>