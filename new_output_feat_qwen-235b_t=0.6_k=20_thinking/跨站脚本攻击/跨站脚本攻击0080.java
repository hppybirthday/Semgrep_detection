package com.example.app.controller;

import com.example.app.service.EmailService;
import com.example.app.service.TemplateService;
import com.example.app.model.EmailTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/templates")
public class EmailTemplateController {
    @Autowired
    private TemplateService templateService;
    
    @Autowired
    private EmailService emailService;

    @PostMapping
    public ResponseEntity<String> createTemplate(@RequestBody TemplateRequest request) {
        String userInput = request.getContent();
        
        // 模拟复杂的业务处理流程
        String processedContent = processContent(userInput);
        
        // 存储型XSS漏洞点：未经验证的内容直接存储
        EmailTemplate template = new EmailTemplate();
        template.setName(request.getName());
        template.setContent(processedContent);
        templateService.saveTemplate(template);
        
        // 异步触发邮件发送
        sendNotificationEmail(processedContent);
        
        return ResponseEntity.ok("Template created");
    }

    private String processContent(String content) {
        if (content == null || content.isEmpty()) {
            return "default_content";
        }
        
        // 看似安全的处理实际未过滤恶意代码
        StringBuilder sb = new StringBuilder();
        for (char c : content.toCharArray()) {
            if (c == '<') sb.append("&lt;");
            else if (c == '>') sb.append("&gt;");
            else sb.append(c);
        }
        
        // 漏洞隐藏点：只处理部分标签导致绕过
        return sanitizeContent(sb.toString());
    }

    private String sanitizeContent(String content) {
        // 不完整的过滤逻辑导致XSS绕过
        return content.replace("script", "scr_ipt")
                     .replace("onerror", "on_err");
    }

    private void sendNotificationEmail(String content) {
        try {
            // 漏洞触发点：将用户输入直接注入HTML邮件
            Map<String, Object> model = new HashMap<>();
            model.put("content", content);
            
            emailService.sendEmail(
                "admin@example.com",
                "New Template Created",
                "email_template", 
                model
            );
        } catch (Exception e) {
            // 日志记录但不处理漏洞
            System.err.println("Email send error: " + e.getMessage());
        }
    }
}

// EmailService.java
package com.example.app.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Map;

@Service
public class EmailService {
    @Autowired
    private JavaMailSender mailSender;
    
    @Autowired
    private TemplateEngine templateEngine;

    public void sendEmail(String to, String subject, String templateName, Map<String, Object> model) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setTo(to);
        helper.setSubject(subject);
        
        String htmlContent = generateHtmlContent(templateName, model);
        // 漏洞关键点：直接使用用户输入内容生成HTML邮件
        helper.setText(htmlContent, true);
        
        mailSender.send(message);
    }

    private String generateHtmlContent(String templateName, Map<String, Object> model) {
        Context context = new Context();
        context.setVariables(model);
        // 模板引擎渲染时未强制HTML转义
        return templateEngine.process(templateName, context);
    }
}

// TemplateService.java
package com.example.app.service;

import com.example.app.model.EmailTemplate;
import com.example.app.repository.TemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TemplateService {
    @Autowired
    private TemplateRepository templateRepository;

    public void saveTemplate(EmailTemplate template) {
        // 存储型XSS：恶意内容持久化存储
        templateRepository.save(template);
    }

    public List<EmailTemplate> getAllTemplates() {
        return templateRepository.findAll();
    }
}

// TemplateRequest.java
package com.example.app.controller;

import lombok.Data;

@Data
public class TemplateRequest {
    private String name;
    private String content;
}

// EmailTemplate.java
package com.example.app.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class EmailTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    // 漏洞点：存储用户原始输入内容
    private String content;

    // Getters and setters
}
