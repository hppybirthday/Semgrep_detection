package com.chat.app;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/chat")
public class ChatController {
    private final ChatService chatService = new ChatService();

    @GetMapping
    public String getChatPage() {
        return "chat";
    }

    @PostMapping("/send")
    @ResponseBody
    public List<String> sendMessage(@RequestParam String user, @RequestParam String message) {
        chatService.processAndStoreMessage(user, message);
        return chatService.getFormattedMessages();
    }
}

class ChatService {
    private final List<ChatMessage> messageStore = new ArrayList<>();
    private static final String[] SAFE_TAGS = {"b", "i", "u"};

    void processAndStoreMessage(String user, String rawMessage) {
        String filtered = filterInput(rawMessage);
        ChatMessage msg = new ChatMessage(user, filtered);
        messageStore.add(msg);
    }

    List<String> getFormattedMessages() {
        List<String> formatted = new ArrayList<>();
        for (ChatMessage msg : messageStore) {
            formatted.add(String.format("<div><b>%s</b>: %s</div>", msg.user, msg.content));
        }
        return formatted;
    }

    private String filterInput(String input) {
        if (input == null) return "";
        
        // Misleading: Only escapes basic tags but allows script via special cases
        String result = input.replace("<script", "&lt;script");
        result = result.replace("</script>", "&lt;/script&gt;");
        
        // Vulnerability: Incomplete tag filtering allows malformed tags to pass through
        for (String tag : SAFE_TAGS) {
            result = result.replaceAll("(?i)<\\\\s*" + tag + "\\\\s*>", "<$1>");
            result = result.replaceAll("(?i)<\\\\s*/\\\\s*" + tag + "\\\\s*>", "</$1>");
        }
        
        return result;
    }
}

class ChatMessage {
    final String user;
    final String content;

    ChatMessage(String user, String content) {
        this.user = sanitizeUser(user);
        this.content = content;
    }

    private String sanitizeUser(String user) {
        // Incomplete sanitization allows CSS injection
        return user.replaceAll("[<>]", "");
    }
}

/*
攻击场景分析：
1. 漏洞触发层级：控制器层的message参数直接传递给服务层
2. 攻击面特征：用户消息内容被存储并在聊天界面持久化显示
3. 数据处理漏洞：filterInput方法看似过滤了script标签，但通过：
   - 大小写绕过：<SCRIPT>alert(1)</SCRIPT>
   - 特殊空格：<script\\x20>alert(1)</script>
   - 闭合标签遗漏：<div onmouseover=alert(1)>恶意内容</div>
4. XSS构造上下文：直接插入HTML div容器的innerHTML
5. 漏洞成因：未使用成熟的HTML转义库，正则表达式不完整
6. 攻击后果：窃取用户会话Cookie、发起CSRF攻击、页面内容篡改
*/