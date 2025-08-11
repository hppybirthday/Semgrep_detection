package com.enterprise.mail.controller;

import com.enterprise.mail.exception.InvalidEmailException;
import com.enterprise.mail.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class EmailController {
    @Autowired
    private EmailService emailService;

    @PostMapping("/send")
    public ModelAndView sendEmail(@RequestParam("recipient") String recipientEmail,
                                 @RequestParam("message") String messageContent) {
        ModelAndView modelAndView = new ModelAndView("error");
        try {
            emailService.validateAndSend(recipientEmail, messageContent);
            modelAndView.setViewName("success");
        } catch (InvalidEmailException e) {
            // 错误信息直接包含用户输入内容
            modelAndView.addObject("error", e.getMessage());
        } catch (Exception e) {
            modelAndView.addObject("error", "Unexpected error: " + e.getMessage());
        }
        return modelAndView;
    }
}

package com.enterprise.mail.service;

import com.enterprise.mail.exception.InvalidEmailException;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";

    public void validateAndSend(String recipient, String content) throws InvalidEmailException {
        if (!isValidEmail(recipient)) {
            // 直接将用户输入拼接到异常信息中
            throw new InvalidEmailException("Invalid recipient email: " + recipient);
        }
        // 模拟邮件发送逻辑
        if (content.contains("<script>")) {
            throw new InvalidEmailException("Content contains forbidden characters: " + content);
        }
        // 实际发送邮件代码...
    }

    private boolean isValidEmail(String email) {
        return email != null && email.matches(EMAIL_REGEX);
    }

    // 看似安全的转义方法但未被使用
    @SuppressWarnings("unused")
    private String sanitizeInput(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

package com.enterprise.mail.exception;

public class InvalidEmailException extends Exception {
    public InvalidEmailException(String message) {
        super(message);
    }
}

// Thymeleaf模板 error.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <div class="error" th:text="${error}"></div> <!-- 存在XSS漏洞的渲染方式 -->
// </body>
// </html>