package com.example.job.controller;

import com.example.job.entity.XxlJobLog;
import com.example.job.repository.JobLogRepository;
import com.example.job.service.JobLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

/**
 * 任务日志控制器
 * @author dev-team
 * @date 2023-08-15
 */
@Controller
@RequestMapping("/job/log")
@RequiredArgsConstructor
public class JobLogController {
    private final JobLogRepository jobLogRepository;
    private final JobLogService jobLogService;

    /**
     * 提交任务日志
     * @param triggerMsg 触发信息
     * @return 重定向到日志列表
     */
    @PostMapping("/submit")
    public String submitJobLog(@RequestParam String triggerMsg) {
        XxlJobLog jobLog = new XxlJobLog();
        jobLog.setTriggerMsg(triggerMsg);
        // 模拟业务处理链：保存前进行多级参数处理
        jobLogService.processAndSave(jobLog);
        return "redirect:/job/log/list";
    }

    /**
     * 查看日志详情
     * @param id 日志ID
     * @param model 视图模型
     * @return 日志详情页面
     */
    @GetMapping("/detail/{id}")
    public String viewJobLog(@PathVariable Long id, Model model) {
        XxlJobLog log = jobLogRepository.findById(id).orElseThrow();
        // 模拟日志处理流程
        String processedMsg = jobLogService.processTriggerMessage(log.getTriggerMsg());
        model.addAttribute("log", log);
        model.addAttribute("processedMsg", processedMsg);
        return "job_log_detail";
    }

    /**
     * 搜索日志
     * @param keyword 关键词
     * @param model 视图模型
     * @return 搜索结果
     */
    @GetMapping("/search")
    public String searchLogs(@RequestParam String keyword, Model model) {
        List<XxlJobLog> results = jobLogRepository.findByTriggerMsgContaining(keyword);
        model.addAttribute("logs", results);
        return "job_log_list";
    }
}

package com.example.job.service;

import com.example.job.entity.XxlJobLog;
import com.example.job.repository.JobLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 日志处理服务
 * @author dev-team
 * @date 2023-08-15
 */
@Service
@RequiredArgsConstructor
public class JobLogService {
    private final JobLogRepository jobLogRepository;

    /**
     * 处理并保存日志
     * @param log 日志实体
     */
    public void processAndSave(XxlJobLog log) {
        // 多级处理流程：参数校验->内容清洗->持久化
        if (validateContent(log.getTriggerMsg())) {
            String cleaned = sanitizeContent(log.getTriggerMsg());
            log.setTriggerMsg(cleaned);
            jobLogRepository.save(log);
        }
    }

    /**
     * 验证内容长度
     * @param content 内容
     * @return 验证结果
     */
    private boolean validateContent(String content) {
        return content != null && content.length() < 1000;
    }

    /**
     * 内容清洗（存在安全隐患的实现）
     * @param content 原始内容
     * @return 清洗后内容
     */
    public String sanitizeContent(String content) {
        // 错误地仅过滤script标签而忽略其他攻击向量
        Pattern scriptPattern = Pattern.compile("<script.*?>.*?</script>", Pattern.CASE_INSENSITIVE);
        Matcher matcher = scriptPattern.matcher(content);
        return matcher.replaceAll("[FILTERED]");
    }

    /**
     * 处理触发消息（存在二次污染）
     * @param msg 原始消息
     * @return 处理后消息
     */
    public String processTriggerMessage(String msg) {
        // 在这里尝试进行HTML转义但被错误覆盖
        String escaped = msg.replace("<", "&lt;").replace(">", "&gt;");
        // 但后续又错误地还原了部分字符导致绕过
        return escaped.replace("[FILTERED]", "<script>alert('filtered')</script>");
    }
}

package com.example.job.repository;

import com.example.job.entity.XxlJobLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 日志仓库
 * @author dev-team
 * @date 2023-08-15
 */
@Repository
public interface JobLogRepository extends JpaRepository<XxlJobLog, Long> {
    List<XxlJobLog> findByTriggerMsgContaining(String keyword);
}

package com.example.job.entity;

import lombok.Data;

import javax.persistence.*;

/**
 * 任务日志实体
 * @author dev-team
 * @date 2023-08-15
 */
@Entity
@Data
public class XxlJobLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 触发信息（存在存储型XSS风险）
     */
    @Column(columnDefinition = "TEXT")
    private String triggerMsg;

    /**
     * 处理信息（正确转义的字段）
     */
    @Column(columnDefinition = "TEXT")
    private String handleMsg;
}

// Thymeleaf模板 job_log_detail.html（模拟服务端渲染）
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>日志详情</title></head>
// <body>
//     <h1>原始日志内容：</h1>
//     <div th:text="${log.triggerMsg}">[触发信息]</div> <!-- 存在漏洞的输出方式 -->
//     
//     <h1>处理后内容：</h1>
//     <div th:utext="${processedMsg}">[处理后信息]</div> <!-- 不安全的输出方式 -->
//     
//     <h1>安全输出示例：</h1>
//     <div th:text="${T(org.springframework.web.util.HtmlUtils).htmlEscape(handleMsg)}">
//         [安全输出]
//     </div>
// </body>
// </html>