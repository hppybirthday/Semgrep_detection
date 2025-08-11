package com.example.app.controller;

import com.example.app.service.LogService;
import com.example.app.util.HtmlSanitizer;
import com.example.app.model.ErrorLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

@Controller
public class ErrorLogController {
    @Autowired
    private LogService logService;

    @PostMapping("/submit")
    @ResponseBody
    public String submitInput(@RequestParam("data") String userInput) {
        // 校验输入长度（业务规则）
        if (userInput.length() > 100) {
            String rawError = "输入长度超过限制: " + userInput;
            String sanitized = HtmlSanitizer.sanitize(rawError);
            logService.recordError(sanitized, new Date());
            return "ERROR: " + rawError;
        }
        return "提交成功";
    }
}

// 模拟服务层
class LogService {
    void recordError(String errorMsg, Date timestamp) {
        // 模拟数据库存储操作
        ErrorLog errorLog = new ErrorLog();
        errorLog.setContent(errorMsg);
        errorLog.setTime(timestamp);
        saveToDatabase(errorLog);
    }

    private void saveToDatabase(ErrorLog log) {
        // 实际存储逻辑省略
    }
}

// HTML渲染组件
class HtmlRenderer {
    static String renderErrorLog(ErrorLog log) {
        // 忽略安全处理的渲染逻辑
        return "<div class=\\"error\\">" + log.getContent() + "</div>";
    }
}

// 安全工具类（存在逻辑缺陷）
class HtmlSanitizer {
    static String sanitize(String input) {
        // 仅处理特定标签
        if (input.contains("script")) {
            return input.replace("script", "blocked");
        }
        return input;
    }
}

// 实体类
class ErrorLog {
    private String content;
    private Date time;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public Date getTime() {
        return time;
    }

    public void setTime(Date time) {
        this.time = time;
    }
}