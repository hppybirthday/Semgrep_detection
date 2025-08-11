package com.example.bank.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/job-logs")
public class XxlJobLogController {
    
    @Autowired
    private JobLogService jobLogService;

    @GetMapping("/{jobId}")
    public String viewJobLog(@PathVariable String jobId, Model model) {
        JobLog log = jobLogService.findJobLogById(jobId);
        model.addAttribute("triggerMsg", log.getTriggerMsg());
        model.addAttribute("handleMsg", log.getHandleMsg());
        return "job_log_detail";
    }

    @GetMapping("/jsonp")
    @ResponseBody
    public String getJsonpLog(HttpServletRequest request) {
        String callback = request.getParameter("callback");
        String jobId = request.getParameter("jobId");
        
        JobLog log = jobLogService.findJobLogById(jobId);
        
        // 存在漏洞的JSONP响应构造
        StringBuilder response = new StringBuilder();
        response.append(callback).append("({");
        response.append("\\"jobId\\":\\"").append(log.getId()).append("\\",");
        response.append("\\"triggerMsg\\":\\"").append(log.getTriggerMsg()).append("\\",");
        response.append("\\"handleMsg\\":\\"").append(log.getHandleMsg()).append("\\"");
        response.append("})");
        
        return response.toString();
    }
    
    // 模拟服务层
    static class JobLogService {
        JobLog findJobLogById(String id) {
            // 模拟数据库查询，实际可能包含用户提交的恶意内容
            JobLog log = new JobLog();
            log.setId(id);
            log.setTriggerMsg("<script>alert('xss')</script>");
            log.setHandleMsg("正常执行");
            return log;
        }
    }
    
    static class JobLog {
        private String id;
        private String triggerMsg;
        private String handleMsg;
        
        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public String getTriggerMsg() { return triggerMsg; }
        public void setTriggerMsg(String triggerMsg) { this.triggerMsg = triggerMsg; }
        
        public String getHandleMsg() { return handleMsg; }
        public void setHandleMsg(String handleMsg) { this.handleMsg = handleMsg; }
    }
}