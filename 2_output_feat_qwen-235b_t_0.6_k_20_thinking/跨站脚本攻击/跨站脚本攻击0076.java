package com.example.chatapp.payment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.mail.internet.MimeMessage;
import java.math.BigDecimal;

@RestController
@RequestMapping("/api/payments")
public class PaymentController {
    @Autowired
    private PaymentService paymentService;

    @PostMapping("/request")
    public String processPayment(@RequestParam String username, @RequestParam BigDecimal amount) {
        // 创建支付请求并发送通知邮件
        paymentService.createPaymentRequest(username, amount);
        return "Payment request processed";
    }
}

@Service
class PaymentService {
    @Autowired
    private JavaMailSender mailSender;

    void createPaymentRequest(String username, BigDecimal amount) {
        // 生成支付确认邮件内容
        String emailContent = buildPaymentEmailContent(username, amount);
        
        // 发送邮件通知
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo("user@example.com");
            helper.setSubject("支付请求通知");
            helper.setText(emailContent, true);
            mailSender.send(message);
        } catch (Exception e) {
            // 邮件发送异常处理
        }
    }

    private String buildPaymentEmailContent(String username, BigDecimal amount) {
        // 构建包含用户输入的HTML邮件模板
        StringBuilder content = new StringBuilder();
        content.append("<div class='payment-notice'>");
        content.append("<p>新支付请求</p>");
        content.append("<div class='details'>");
        content.append("<span>用户：").append(username).append("</span>");
        content.append("<span>金额：").append(amount).append("</span>");
        content.append("</div>");
        content.append("</div>");
        return content.toString();
    }
}