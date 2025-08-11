package com.example.app.controller;

import com.example.app.service.FeedbackService;
import com.example.app.util.SecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class FeedbackController {
    @Autowired
    private FeedbackService feedbackService;

    // 提交用户反馈接口
    @PostMapping("/submitFeedback")
    public String handleFeedback(@RequestParam("content") String userInput) {
        // 校验输入长度（业务规则）
        if (userInput.length() > 1000) {
            return "feedback_too_long";
        }
        
        // 预处理输入内容
        String processed = SecurityUtil.sanitizeInput(userInput);
        
        // 存储反馈内容到数据库
        feedbackService.saveFeedback(processed);
        
        return "feedback_submitted";
    }
}

// ------------------------------

package com.example.app.service;

import com.example.app.repository.FeedbackRepository;
import com.example.app.util.ContentProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class FeedbackService {
    @Autowired
    private FeedbackRepository feedbackRepository;

    // 保存反馈内容到数据库
    public void saveFeedback(String content) {
        // 二次处理内容（业务需求）
        String finalContent = ContentProcessor.processContent(content);
        
        // 持久化存储
        feedbackRepository.save(finalContent);
    }
}

// ------------------------------

package com.example.app.util;

import org.springframework.stereotype.Component;

@Component
public class ContentProcessor {
    // 处理内容格式
    public static String processContent(String input) {
        // 替换特殊空格（业务需求）
        return input.replace("\\u00A0", " ");
    }
}

// ------------------------------

package com.example.app.service;

import com.example.app.mail.MailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EmailNotificationService {
    @Autowired
    private MailService mailService;

    // 发送包含反馈内容的通知邮件
    public void sendFeedbackNotification(String content) {
        // 构建邮件内容
        String emailBody = "<div class='content'>" + content + "</div>";
        
        // 发送HTML邮件
        mailService.sendHtmlEmail("admin@example.com", "New Feedback", emailBody);
    }
}

// ------------------------------

package com.example.app.mail;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.thymeleaf.spring6.context.SpringContextUtils;
import org.thymeleaf.spring6.template.SpringTemplateEngine;

import javax.mail.internet.MimeMessage;

@Service
public class MailService {
    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    public MailService(JavaMailSender mailSender, SpringTemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    // 发送HTML格式邮件
    public void sendHtmlEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            message.setContent(htmlContent, "text/html;charset=UTF-8");
            mailSender.send(message);
        } catch (Exception e) {
            // 邮件发送失败处理
        }
    }
}