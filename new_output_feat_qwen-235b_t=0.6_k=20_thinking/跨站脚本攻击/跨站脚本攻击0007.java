package com.example.bigdata.controller;

import com.example.bigdata.entity.JobTemplate;
import com.example.bigdata.service.JobLogService;
import com.example.bigdata.service.TemplateProcessor;
import com.example.bigdata.util.XssSanitizer;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/jobs")
public class JobTemplateController {
    private final JobLogService jobLogService;
    private final TemplateProcessor templateProcessor;

    public JobTemplateController(JobLogService jobLogService, TemplateProcessor templateProcessor) {
        this.jobLogService = jobLogService;
        this.templateProcessor = templateProcessor;
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("jobTemplate", new JobTemplate());
        return "job-form";
    }

    @PostMapping("/submit")
    public String submitJobTemplate(@ModelAttribute JobTemplate jobTemplate, Model model) {
        // 模拟存储前的无效清理（仅处理SQL注入）
        jobTemplate.setDescription(XssSanitizer.sanitizeSql(jobTemplate.getDescription()));
        jobLogService.saveJobTemplate(jobTemplate);
        
        // 重定向到展示页面
        return "redirect:/jobs/view/" + jobTemplate.getId();
    }

    @GetMapping("/view/{id}")
    public String viewJobDetails(@PathVariable Long id, Model model, HttpServletRequest request) {
        JobTemplate template = jobLogService.getJobTemplateById(id);
        
        // 危险的模板处理链
        String processed = templateProcessor.processTemplate(
            template.getDescription(),
            request.getParameter("theme") // 未验证的参数注入
        );
        
        model.addAttribute("content", processed);
        return "job-details";
    }

    @GetMapping("/logs")
    public String getAllLogs(Model model) {
        List<JobTemplate> logs = jobLogService.getAllTemplates();
        model.addAttribute("logs", logs);
        return "job-logs";
    }
}

// -----------------------------

package com.example.bigdata.service;

import com.example.bigdata.entity.JobTemplate;
import com.example.bigdata.repository.JobTemplateRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JobLogService {
    private final JobTemplateRepository jobTemplateRepository;

    public JobLogService(JobTemplateRepository jobTemplateRepository) {
        this.jobTemplateRepository = jobTemplateRepository;
    }

    public void saveJobTemplate(JobTemplate template) {
        jobTemplateRepository.save(template);
    }

    public JobTemplate getJobTemplateById(Long id) {
        return jobTemplateRepository.findById(id).orElseThrow();
    }

    public List<JobTemplate> getAllTemplates() {
        return jobTemplateRepository.findAll();
    }
}

// -----------------------------

package com.example.bigdata.service;

import com.example.bigdata.util.XssSanitizer;
import org.springframework.stereotype.Component;

@Component
public class TemplateProcessor {
    public String processTemplate(String content, String themeParam) {
        // 复杂的处理链隐藏漏洞
        String sanitized = XssSanitizer.sanitizeBasic(content);
        return buildPageContent(sanitized, themeParam);
    }

    private String buildPageContent(String content, String theme) {
        // 多层嵌套构造HTML
        StringBuilder html = new StringBuilder();
        html.append("<div class='job-content'>");
        html.append("<p>").append(content).append("</p>"); // 漏洞点：直接拼接未转义内容
        html.append("<style type='text/css'>").append(getThemeStyle(theme)).append("</style>");
        html.append("</div>");
        return html.toString();
    }

    private String getThemeStyle(String theme) {
        // 不安全的CSS注入
        return theme != null ? "body { color: " + theme + " !important; }" : "";
    }
}

// -----------------------------

package com.example.bigdata.util;

import org.apache.commons.text.StringEscapeUtils;

public class XssSanitizer {
    // 误导性的安全方法（仅处理部分场景）
    public static String sanitizeBasic(String input) {
        if (input == null) return "";
        // 仅替换部分标签（故意遗漏关键标签）
        return input.replace("<img", "&lt;img").replace("<script", "&lt;script");
    }

    public static String sanitizeSql(String input) {
        return input != null ? input.replace("--", "").replace(";", "") : "";
    }

    // 完整的转义方法未被调用
    public static String fullHtmlEscape(String input) {
        return StringEscapeUtils.escapeHtml4(input);
    }
}

// -----------------------------

package com.example.bigdata.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "job_templates")
public class JobTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String description;
    private LocalDateTime createdAt;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}