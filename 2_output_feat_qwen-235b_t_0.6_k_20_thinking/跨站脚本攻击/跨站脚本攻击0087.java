package com.example.payment.callback;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;
import java.util.logging.Logger;

@Controller
public class CallbackController {
    private static final Logger LOGGER = Logger.getLogger(CallbackController.class.getName());
    private final MessageProcessor messageProcessor = new MessageProcessor();

    @RequestMapping("/payment/return")
    public String handleCallback(@RequestParam("status") String status,
                                @RequestParam("message") String userMessage) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        
        if ("success".equals(status)) {
            ProcessResult result = messageProcessor.process(userMessage);
            request.setAttribute("msg", result.getMessage());
            LOGGER.info("Payment success with message: " + userMessage);
        } else {
            request.setAttribute("msg", "Payment failed");
        }
        
        return "payment_result";
    }
}

class ProcessResult {
    private final String message;
    private final boolean valid;

    ProcessResult(String message, boolean valid) {
        this.message = message;
        this.valid = valid;
    }

    public String getMessage() {
        return message;
    }

    public boolean isValid() {
        return valid;
    }
}

class MessageProcessor {
    private static final int MAX_LENGTH = 200;

    ProcessResult process(String input) {
        if (input == null || input.isEmpty()) {
            return new ProcessResult("No message provided", false);
        }
        
        if (input.length() > MAX_LENGTH) {
            input = input.substring(0, MAX_LENGTH);
        }
        
        // 记录输入内容用于审计
        AuditLogger.logInput(input);
        
        return new ProcessResult(input, true);
    }
}

class AuditLogger {
    static void logInput(String content) {
        // 模拟审计日志记录
        System.out.println("[AUDIT] Input received: " + content);
    }
}