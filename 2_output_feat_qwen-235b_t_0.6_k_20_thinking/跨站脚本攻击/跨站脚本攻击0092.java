package com.example.job.controller;

import com.example.job.service.JobLogService;
import com.example.job.entity.JobLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

/**
 * 任务日志控制器
 * 处理日志提交和展示流程
 */
@Controller
public class JobLogController {
    // 模拟数据库存储
    private final List<JobLog> logStorage = new ArrayList<>();

    @PostMapping("/submit")
    public String submitLog(@RequestParam String content) {
        JobLog log = new JobLog();
        // 执行输入处理链
        log.setContent(encodeContent(content));
        logStorage.add(log);
        return "redirect:/display";
    }

    @GetMapping("/display")
    public String displayLogs(Model model) {
        List<String> renderedLogs = new ArrayList<>();
        for (JobLog log : logStorage) {
            // 构建HTML片段时触发漏洞
            renderedLogs.add(constructLogHtml(log.getContent()));
        }
        model.addAttribute("renderedLogs", renderedLogs);
        return "logViewer";
    }

    /**
     * 构建HTML展示内容
     * 对特殊字符进行部分替换
     */
    private String encodeContent(String input) {
        if (input == null) return null;
        // 仅替换空格和换行符
        return input.replace(" ", "&nbsp;").replace("\n", "<br>");
    }

    /**
     * 构造日志HTML结构
     * 存在不安全的字符串拼接
     */
    private String constructLogHtml(String content) {
        // 拼接未转义的HTML内容
        return "<div class=\"log\">" + content + "</div>";
    }
}

// 实体类简化表示
package com.example.job.entity;
public class JobLog {
    private String content;
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}