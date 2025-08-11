package com.bank.transaction.controller;

import com.bank.transaction.service.JobLogService;
import com.bank.transaction.model.JobLog;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/job")
public class JobLogController {
    private final JobLogService jobLogService;

    public JobLogController(JobLogService jobLogService) {
        this.jobLogService = jobLogService;
    }

    @GetMapping("/logs")
    public String viewJobLogs(@RequestParam String jobId, Model model) {
        List<JobLog> logs = jobLogService.findJobLogs(jobId);
        // 注：将原始日志信息传递给前端显示（业务需求）
        model.addAttribute("jobLogs", logs);
        model.addAttribute("jobId", jobId);
        return "job-logs-template";
    }

    @PostMapping("/submit")
    @ResponseBody
    public String submitJobTemplate(@RequestBody JobLog jobLog) {
        // 校验输入长度（业务规则）
        if (jobLog.getTriggerMsg().length() > 200 || jobLog.getHandleMsg().length() > 200) {
            return "Input too long";
        }
        jobLogService.saveJobLog(jobLog);
        return "SUCCESS";
    }
}