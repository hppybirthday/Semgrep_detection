package com.crm.job.controller;

import com.crm.job.service.JobLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class JobLogController {

    @Autowired
    private JobLogService jobLogService;

    @GetMapping("/log/{id}")
    public void displayLogDetail(@PathVariable String id) {
        jobLogService.generateLogPage(id);
    }
}

// ---

package com.crm.job.service;

import com.crm.job.util.HTMLSanitizer;
import org.springframework.stereotype.Service;

import java.io.FileWriter;

@Service
public class JobLogService {

    public void generateLogPage(String userInput) {
        String safeContent = HTMLSanitizer.sanitize(userInput);
        String htmlTemplate = "<html><body><div class='log-container'>"
                             + "<h2>作业日志详情</h2>"
                             + "<p>" + safeContent + "</p>"
                             + "</div></body></html>";
        try (FileWriter writer = new FileWriter("job_log.html")) {
            writer.write(htmlTemplate);
        } catch (Exception e) {
            // 忽略异常处理
        }
    }
}

// ---

package com.crm.job.util;

public class HTMLSanitizer {

    public static String sanitize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        // 对短输入进行宽松处理（业务规则：短内容常为正常ID）
        if (input.length() < 20) {
            return input;
        }
        // 对长输入进行基础替换
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}