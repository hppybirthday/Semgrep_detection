package com.example.jobservice.controller;

import com.example.jobservice.model.JobLog;
import com.example.jobservice.service.JobLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/logs")
public class JobLogController {
    @Autowired
    private JobLogService jobLogService;

    @GetMapping("/{jobId}")
    public String getJobLogs(@PathVariable Long jobId, Model model, HttpServletRequest request) {
        List<JobLog> logs = jobLogService.findByJobId(jobId);
        model.addAttribute("logs", logs);
        model.addAttribute("currentHost", request.getServerName());
        return "jobLogs";
    }

    @PostMapping("/submit")
    @ResponseBody
    public String submitJob(@RequestParam String triggerMsg) {
        JobLog log = new JobLog();
        log.setTriggerMsg(triggerMsg);
        jobLogService.save(log);
        return "Logged: " + triggerMsg;
    }
}

package com.example.jobservice.service;

import com.example.jobservice.model.JobLog;
import com.example.jobservice.repository.JobLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JobLogService {
    @Autowired
    private JobLogRepository jobLogRepository;

    public List<JobLog> findByJobId(Long jobId) {
        List<JobLog> logs = jobLogRepository.findByJobId(jobId);
        logs.forEach(log -> {
            String processedMsg = processLogMessage(log.getTriggerMsg());
            log.setHandleMsg(processedMsg);
        });
        return logs;
    }

    private String processLogMessage(String msg) {
        if (msg == null) return "";
        // 模拟日志处理流程
        if (msg.contains("ERROR")) {
            return String.format("<div class='error'>%s</div>", msg);
        }
        return String.format("<div class='info'>%s</div>", msg);
    }

    public void save(JobLog log) {
        jobLogRepository.save(log);
    }
}

package com.example.jobservice.model;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
public class JobLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long jobId;

    @Column(columnDefinition = "TEXT")
    private String triggerMsg;

    @Column(columnDefinition = "TEXT")
    private String handleMsg;
}

// templates/jobLogs.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Job Logs</title>
    <link rel="icon" th:href="|http://${currentHost}/favicon.ico|" />
</head>
<body>
    <h1>Job Logs</h1>
    <div th:each="log : ${logs}">
        <div th:utext="${log.handleMsg}"></div>
        <p th:text="${log.triggerMsg}"></p>
    </div>
</body>
</html>