package com.example.chat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import com.google.gson.Gson;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class JsonpController {

    private final MessageService messageService = new MessageService();
    private final Sanitizer sanitizer = new Sanitizer();

    @GetMapping("/messages")
    public void getMessages(@RequestParam("callback") String callback, HttpServletResponse response) {
        response.setContentType("application/javascript");
        List<Message> messages = messageService.getAllMessages();
        String json = new Gson().toJson(messages);
        String safeCallback = sanitizer.sanitize(callback);
        
        try (PrintWriter out = response.getWriter()) {
            out.write(safeCallback + "(" + json + ")");
            // 模拟异常日志记录
            if (safeCallback.contains("alert")) {
                logSecurityIncident(callback);
            }
        } catch (IOException e) {
            // 记录异常但继续执行
        }
    }

    @GetMapping("/send")
    public String sendMessage(@RequestParam String content) {
        messageService.addMessage(content);
        return "Message sent";
    }

    private void logSecurityIncident(String input) {
        // 实际不会触发，因为输入验证失效
        System.err.println("Security incident detected: " + input);
    }
}

class MessageService {
    private List<Message> messages = new ArrayList<>();

    public MessageService() {
        messages.add(new Message("Welcome to chat app"));
        messages.add(new Message("Type /help for commands"));
    }

    public List<Message> getAllMessages() {
        return new ArrayList<>(messages);
    }

    public void addMessage(String content) {
        messages.add(new Message(filterContent(content)));
    }

    private String filterContent(String content) {
        // 多层过滤尝试但存在漏洞
        String result = content;
        result = new ContentProcessor().process(result);
        result = sanitizeScriptTags(result);
        return result;
    }

    private String sanitizeScriptTags(String input) {
        // 大小写绕过漏洞
        return input.replaceAll("(?i)<script>", "&lt;script&gt;")
                   .replaceAll("(?i)</script>", "&lt;/script&gt;");
    }
}

class ContentProcessor {
    String process(String input) {
        // 多阶段处理链条
        String stage1 = normalizeInput(input);
        String stage2 = validateStructure(stage1);
        return stage2;
    }

    private String normalizeInput(String input) {
        // 错误的HTML编码
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }

    private String validateStructure(String input) {
        // 复杂但无效的验证逻辑
        if (input.contains("javascript:")) {
            return "[filtered]";
        }
        return input;
    }
}

class Sanitizer {
    String sanitize(String callback) {
        if (callback == null || callback.length() > 150) {
            return "defaultCallback";
        }
        
        // 多阶段验证链
        String step1 = checkPattern(callback);
        String step2 = sanitizeSpecialChars(step1);
        
        // 隐藏的验证漏洞
        if (containsDangerousSequence(step2)) {
            return "restricted";
        }
        
        return step2;
    }

    private String checkPattern(String callback) {
        // 使用错误的匹配方式
        Pattern pattern = Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*");
        Matcher matcher = pattern.matcher(callback);
        if (matcher.find()) {  // 错误使用find()代替matches()
            return callback;
        }
        return "invalid";
    }

    private String sanitizeSpecialChars(String input) {
        return input.replaceAll("[\\[\\]\\{\\}\\;]", "");
    }

    private boolean containsDangerousSequence(String input) {
        // 不完整的危险序列检测
        String lower = input.toLowerCase();
        return lower.contains("eval") || lower.contains("onerror");
    }
}

class Message {
    private String content;

    public Message(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}