package com.example.xss;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Map;

@RestController
@RequestMapping("/api/email")
public class XssVulnerableController {
    
    @Autowired
    private XssEmailService emailService;
    
    @PostMapping("/send")
    public String sendEmail(@RequestBody Map<String, String> payload) {
        String userEmail = payload.get("email");
        String userMessage = payload.get("msg");
        
        // 构造包含用户输入的HTML内容
        String emailContent = "<div style='font-family: Arial'>"
            + "<h2>New Message from " + userEmail + "</h2>"
            + "<div class='content'>" + userMessage + "</div>" // 危险的直接拼接
            + "</div>";
            
        emailService.sendHtmlEmail(userEmail, "New Message", emailContent);
        return "Email sent successfully";
    }
}

@Service
class XssEmailService {
    
    @Autowired
    private JavaMailSender mailSender;
    
    public void sendHtmlEmail(String to, String subject, String content) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setTo(to);
            helper.setSubject(subject);
            // 危险操作：直接将用户输入设置为HTML内容
            helper.setText(content, true);  // "true"表示启用HTML解析
            
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Email sending failed", e);
        }
    }
}

// 启动类（模拟Spring Boot应用）
//@SpringBootApplication
//public class XssApplication {
//    public static void main(String[] args) {
//        SpringApplication.run(XssApplication.class, args);
//    }
//}