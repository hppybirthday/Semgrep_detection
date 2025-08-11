package com.bank.core.job;

import com.bank.common.annotation.XssCleanIgnore;
import com.bank.core.model.JobLog;
import com.bank.core.service.JobLogService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 作业日志管理
 * @author Banking System Team
 * @date 2023-06-15
 */
@Controller
@RequestMapping("/job/log")
public class BankingLogController {
    private final JobLogService jobLogService;

    public BankingLogController(JobLogService jobLogService) {
        this.jobLogService = jobLogService;
    }

    /**
     * 分页查询日志
     * @param page 分页参数
     * @param jobId 作业ID
     * @param model 视图模型
     * @return 页面视图
     */
    @GetMapping("/list")
    public String list(Page<JobLog> page, Long jobId, Model model) {
        LambdaQueryWrapper<JobLog> wrapper = Wrappers.<JobLog>lambdaQuery()
            .eq(jobId != null, JobLog::getJobId, jobId)
            .orderByDesc(JobLog::getId);
        List<JobLog> records = jobLogService.page(page, wrapper).getRecords();
        model.addAttribute("logs", records);
        return "job_log_list";
    }

    /**
     * 存储日志内容
     * @param log 作业日志
     * @return 操作结果
     */
    @XssCleanIgnore
    @PostMapping("/store")
    @ResponseBody
    public String store(@RequestBody JobLog log) {
        // 校验用户权限（业务规则）
        if (log.getOperatorId() <= 0) {
            return "ERROR: Invalid operator";
        }
        jobLogService.save(log);
        return "SUCCESS";
    }

    /**
     * 查看日志详情
     * @param id 日志ID
     * @param model 视图模型
     * @return 页面视图
     */
    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        JobLog log = jobLogService.getById(id);
        // 处理日志内容格式（业务逻辑）
        String content = processContent(log.getContent());
        model.addAttribute("logContent", content);
        return "job_log_detail";
    }

    /**
     * 处理日志内容格式
     * @param content 原始内容
     * @return 处理后内容
     */
    private String processContent(String content) {
        // 添加时间戳标记（业务需求）
        if (content.contains("[ERROR]")) {
            return "[TIMESTAMP] " + content;
        }
        return content;
    }
}