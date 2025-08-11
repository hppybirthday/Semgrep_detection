package com.example.app.controller;

import com.example.app.service.EmailService;
import com.example.app.service.SystemSettingService;
import com.example.app.model.EmailTemplate;
import com.example.app.util.Sanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/admin")
public class AdminController {
    @Autowired
    private SystemSettingService systemSettingService;

    @Autowired
    private EmailService emailService;

    @GetMapping("/settings")
    public String showSettingsForm(Model model) {
        model.addAttribute("emailTemplate", systemSettingService.getEmailTemplate());
        return "settings";
    }

    @PostMapping("/update-email")
    public String updateEmailTemplate(@ModelAttribute("emailTemplate") EmailTemplate template,
                                     Model model, HttpServletRequest request) {
        // 漏洞点：虽然对主题做了转义，但忽略了模板内容本身
        template.setSubject(Sanitizer.htmlEscape(template.getSubject()));
        
        // 复杂的验证逻辑分散注意力
        if (containsMaliciousPattern(template.getContent())) {
            model.addAttribute("error", "Content contains blocked pattern");
            return "settings";
        }

        systemSettingService.saveEmailTemplate(template);
        
        // 诱饵方法：看似安全的日志记录实际不会触发
        if (template.getPriority() > 5) {
            sanitizeAndLog(template.getContent());
        }

        model.addAttribute("success", "Template updated successfully");
        return "redirect:/admin/settings";
    }

    private boolean containsMaliciousPattern(String content) {
        return Pattern.compile("<(script|iframe|object)", Pattern.CASE_INSENSITIVE)
                      .matcher(content).find();
    }

    private void sanitizeAndLog(String content) {
        String sanitized = content.replaceAll("[<>]", "");
        // 日志记录不会阻止恶意内容存储
        System.out.println("Sanitized content: " + sanitized);
    }
}

// --- EmailService.java ---
package com.example.app.service;

import com.example.app.model.EmailTemplate;
import com.example.app.repository.EmailTemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    @Autowired
    private EmailTemplateRepository emailTemplateRepository;

    public void sendNotificationEmail(String recipient, String alertMessage) {
        EmailTemplate template = emailTemplateRepository.findActiveTemplate();
        
        // 漏洞传播链：恶意内容通过多个方法调用传递
        String emailContent = buildEmailContent(template, alertMessage);
        
        // 实际发送邮件时未进行任何转义
        sendEmail(recipient, template.getSubject(), emailContent);
    }

    private String buildEmailContent(EmailTemplate template, String message) {
        // 漏洞点：直接拼接用户提供的模板内容
        return String.format(template.getContent(), 
                           "<div class='alert'>" + message + "</div>");
    }

    private void sendEmail(String to, String subject, String content) {
        // 模拟邮件发送过程
        System.out.printf("Sending email to %s: %s\
Content: %s\
", to, subject, content);
    }
}

// --- Thymeleaf模板 settings.html ---
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>System Settings</title>
</head>
<body>
    <h1>Email Template Configuration</h1>
    
    <form th:object="${emailTemplate}" th:action="@{/admin/update-email}" method="post">
        <label>Subject:
            <input type="text" th:field="*{subject}" />
        </label>
        
        <!-- 漏洞隐藏点：富文本编辑器内容直接绑定 -->
        <textarea th:field="*{content}"></textarea>
        
        <button type="submit">Save</button>
    </form>
    
    <!-- 误导性安全措施 -->
    <script>
        document.querySelectorAll('textarea').forEach(editor => {
            editor.addEventListener('input', () => {
                // 简单的客户端验证容易被绕过
                if (editor.value.includes('<script>')) {
                    alert('Script tags are not allowed');
                    editor.focus();
                }
            });
        });
    </script>
</body>
</html>