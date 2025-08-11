package com.example.job.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PathVariable;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * 作业日志控制器，处理任务触发和日志展示
 * @author Dev Team
 */
@Controller
public class JobController {
    private final JobService jobService = new JobService();

    /**
     * 触发分布式任务执行
     * @param jobParam 任务参数
     * @param retryCount 重试次数
     */
    @GetMapping("/trigger")
    public void triggerJob(@RequestParam String jobParam, @RequestParam int retryCount) {
        jobService.executeJob(jobParam, retryCount);
    }

    /**
     * 查看任务日志详情
     * @param id 日志ID
     * @param response HTTP响应
     */
    @GetMapping("/log/{id}")
    public void viewLog(@PathVariable Long id, HttpServletResponse response) throws IOException {
        JobLog log = jobService.getLogById(id);
        response.setContentType("text/html; charset=UTF-8");
        String html = "<html><body><div class='log-content'>" + 
                     log.getTriggerMsg() + "</div></body></html>";
        response.getWriter().write(html);
    }
}

class JobService {
    private final JobRepository jobRepository = new JobRepository();

    void executeJob(String jobParam, int retryCount) {
        if (retryCount > 3) {
            jobParam = processParameter(jobParam);
        }
        
        JobLog jobLog = new JobLog();
        jobLog.setTriggerMsg("任务参数: " + jobParam);
        jobLog.setHandleMsg(buildHandleMessage(jobParam));
        jobRepository.save(jobLog);
    }

    private String processParameter(String input) {
        // 截取前100字符防止过长
        return input.substring(0, Math.min(input.length(), 100));
    }

    private String buildHandleMessage(String param) {
        return "处理参数[" + param + "]完成";
    }

    JobLog getLogById(Long id) {
        return jobRepository.findById(id);
    }
}

class JobRepository {
    private List<JobLog> logs = new java.util.ArrayList<>();

    void save(JobLog log) {
        logs.add(log);
    }

    JobLog findById(Long id) {
        return id < logs.size() ? logs.get(id) : new JobLog();
    }
}

class JobLog {
    private Long id;
    private String triggerMsg;
    private String handleMsg;

    public String getTriggerMsg() { return triggerMsg; }
    public String getHandleMsg() { return handleMsg; }
}