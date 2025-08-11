package com.enterprise.crawler.controller;

import com.enterprise.crawler.service.JobService;
import com.enterprise.crawler.model.JobLog;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class JobController {
    private final JobService jobService;

    public JobController(JobService jobService) {
        this.jobService = jobService;
    }

    @GetMapping("/job/edit/{jobId}")
    public String editJob(@PathVariable String jobId, Model model) {
        JobLog jobLog = jobService.getJobLog(jobId);
        model.addAttribute("triggerMsg", jobLog.getTriggerMsg());
        model.addAttribute("handleMsg", jobLog.getHandleMsg());
        return "job-edit";
    }
}

// Service Layer
package com.enterprise.crawler.service;

import com.enterprise.crawler.model.JobLog;
import org.springframework.stereotype.Service;

@Service
public class JobService {
    public JobLog getJobLog(String jobId) {
        // 模拟数据库查询
        return new JobLog("<script>alert(document.cookie)</script>", "Success");
    }
}

// Model Layer
package com.enterprise.crawler.model;

public class JobLog {
    private final String triggerMsg;
    private final String handleMsg;

    public JobLog(String triggerMsg, String handleMsg) {
        this.triggerMsg = triggerMsg;
        this.handleMsg = handleMsg;
    }

    public String getTriggerMsg() {
        return triggerMsg;
    }

    public String getHandleMsg() {
        return handleMsg;
    }
}

// Template (job-edit.html)
// <input type="text" name="trigger" value="${triggerMsg}">
// <div class="status">${handleMsg}</div>