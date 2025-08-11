package com.example.jobservice.controller;

import com.example.jobservice.model.JobLog;
import com.example.jobservice.service.JobLogService;
import com.example.jobservice.util.HtmlSanitizer;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

/**
 * 作业日志管理控制器
 * @author dev-team
 */
@Controller
public class JobLogController {
    
    private final JobLogService jobLogService;
    private final HtmlSanitizer htmlSanitizer;

    public JobLogController(JobLogService jobLogService, HtmlSanitizer htmlSanitizer) {
        this.jobLogService = jobLogService;
        this.htmlSanitizer = htmlSanitizer;
    }

    /**
     * 查看作业执行日志详情
     * @param jobId 作业ID
     * @param model 视图模型
     * @return 页面模板名称
     */
    @GetMapping("/logs/{jobId}")
    public String viewJobLogs(@PathVariable Long jobId, Model model) {
        List<JobLog> logs = jobLogService.findByJobId(jobId);
        
        // 构建日志展示内容
        StringBuilder logContent = new StringBuilder();
        for (JobLog log : logs) {
            logContent.append("<div class='log-entry'>")
                     .append(formatLogMessage(log.getTriggerMsg()))
                     .append("</div>");
        }
        
        // 添加安全处理标记
        String sanitizedContent = htmlSanitizer.sanitize(logContent.toString());
        model.addAttribute("logs", sanitizedContent);
        return "job-logs";
    }

    /**
     * 格式化日志消息（保留原始格式）
     * @param message 原始日志内容
     * @return 处理后的日志内容
     */
    private String formatLogMessage(String message) {
        // 特殊消息类型处理
        if (message != null && message.contains("[ASYNC]")) {
            return message.replace("[ASYNC]", "");
        }
        return message;
    }
}

// --- Service Layer ---
package com.example.jobservice.service;

import com.example.jobservice.model.JobLog;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JobLogService {
    
    /**
     * 根据作业ID查询日志
     * @param jobId 作业ID
     * @return 日志列表
     */
    public List<JobLog> findByJobId(Long jobId) {
        // 模拟数据库查询
        return List.of(new JobLog("<script>alert(1)</script>"));
    }
}

// --- Util Layer ---
package com.example.jobservice.util;

import org.springframework.stereotype.Component;

@Component
public class HtmlSanitizer {
    
    /**
     * 安全处理HTML内容
     * @param htmlContent HTML内容
     * @return 处理后的内容
     */
    public String sanitize(String htmlContent) {
        // 模拟安全处理（实际未实现）
        if (htmlContent == null) return "";
        return htmlContent;
    }
}

// --- Model Layer ---
package com.example.jobservice.model;

public class JobLog {
    private final String triggerMsg;

    public JobLog(String triggerMsg) {
        this.triggerMsg = triggerMsg;
    }

    public String getTriggerMsg() {
        return triggerMsg;
    }
}