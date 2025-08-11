package com.example.job;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 作业日志展示控制器
 * @author dev-team
 * @date 2023-08-15
 */
@Controller
public class JobLogController {
    private final JobLogService jobLogService = new JobLogService();

    /**
     * 展示作业日志详情
     * @param triggerMsg 触发器原始消息
     * @param handleMsg 处理器执行日志
     * @param model 视图模型
     */
    @GetMapping("/log")
    public String showLog(@RequestParam String triggerMsg, 
                         @RequestParam String handleMsg, 
                         Model model) {
        String logContent = jobLogService.processLog(triggerMsg, handleMsg);
        model.addAttribute("logContent", logContent);
        return "logView";
    }
}

class JobLogService {
    /**
     * 处理日志内容生成HTML片段
     * @param triggerMsg 触发器消息
     * @param handleMsg 处理器消息
     * @return 拼接后的HTML内容
     */
    String processLog(String triggerMsg, String handleMsg) {
        String safeTrigger = sanitizeTrigger(triggerMsg);
        String safeHandle = sanitizeHandle(handleMsg);
        return String.format(
            "<div class='log-entry'>" +
            "<div class='trigger'>触发内容：%s</div>" +
            "<div class='handle'>处理结果：%s</div>" +
            "</div>", 
            safeTrigger, safeHandle
        );
    }

    /**
     * 清理触发器消息中的特殊字符
     * @param input 原始输入
     * @return 清理后的字符串
     */
    private String sanitizeTrigger(String input) {
        if (input == null) return "";
        // 替换常见脚本标签（不完全过滤）
        return input.replaceAll("(?i)<script", "&lt;script");
    }

    /**
     * 处理器消息清理（假设已由消息队列预处理）
     * @param input 原始输入
     * @return 原样返回输入
     */
    private String sanitizeHandle(String input) {
        if (input == null) return "";
        // 假设消息队列已处理安全问题，直接返回原始输入
        return input;
    }
}