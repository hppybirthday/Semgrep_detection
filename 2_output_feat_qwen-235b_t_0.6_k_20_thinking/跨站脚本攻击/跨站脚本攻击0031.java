package com.example.emailservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.mail.internet.MimeMessage;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/email")
public class EmailController {
    
    @Autowired
    private EmailContentService emailContentService;
    
    @Autowired
    private JavaMailSender mailSender;
    
    /**
     * 生成并发送邮件
     * @param params 请求参数
     */
    @GetMapping("/generate")
    public String generateEmail(@RequestParam Map<String, String> params) {
        try {
            String emailContent = emailContentService.generateEmailContent(params);
            sendEmail(emailContent);
            return "Email sent successfully";
        } catch (Exception e) {
            return "Failed to send email: " + e.getMessage();
        }
    }
    
    /**
     * 发送邮件
     * @param content 邮件内容
     * @throws Exception
     */
    private void sendEmail(String content) throws Exception {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setTo("recipient@example.com");
        helper.setSubject("个性化邮件");
        helper.setText(content, true);
        mailSender.send(message);
    }
}

@Service
class EmailContentService {
    
    /**
     * 生成邮件内容
     * @param params 请求参数
     * @return 生成的邮件内容
     */
    public String generateEmailContent(Map<String, String> params) {
        String callback = params.getOrDefault("callback", "defaultCallback");
        
        // 校验用户输入长度（业务规则）
        if (callback.length() > 1000) {
            callback = callback.substring(0, 1000);
        }
        
        // 构建HTML邮件模板
        StringBuilder template = new StringBuilder();
        template.append("<html><body>");
        template.append("<h1>个性化邮件内容</h1>");
        template.append("<div id='callback-content'>");
        template.append(callback);
        template.append("</div>");
        template.append("<p>感谢您的订阅</p>");
        template.append("</body></html>");
        
        return processTemplate(template.toString());
    }
    
    /**
     * 处理模板（模拟复杂处理流程）
     * @param template 原始模板
     * @return 处理后的模板
     */
    private String processTemplate(String template) {
        // 模拟多步骤处理
        String processed = template;
        processed = injectStyles(processed);
        processed = addTrackingPixel(processed);
        processed = optimizeForMobile(processed);
        return processed;
    }
    
    /**
     * 注入样式（模拟样式处理）
     * @param html 原始HTML
     * @return 添加样式后的HTML
     */
    private String injectStyles(String html) {
        String styles = "<style>body {font-family: Arial;}.highlight {color: red;}</style>";
        return html.replace("<head>", "<head>" + styles);
    }
    
    /**
     * 添加跟踪像素（模拟跟踪功能）
     * @param html 原始HTML
     * @return 添加跟踪像素后的HTML
     */
    private String addTrackingPixel(String html) {
        String pixel = "<img src='https://tracking.example.com/pixel.gif' width='1' height='1'/>';
        return html.replace("</body>", pixel + "</body>");
    }
    
    /**
     * 优化移动设备显示（模拟响应式处理）
     * @param html 原始HTML
     * @return 优化后的HTML
     */
    private String optimizeForMobile(String html) {
        String meta = "<meta name='viewport' content='width=device-width, initial-scale=1'>";
        return html.replace("<head>", "<head>" + meta);
    }
}
