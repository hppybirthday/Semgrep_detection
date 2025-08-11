package com.example.chatapp;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Controller
public class ChatController {
    private final List<String> messages = new ArrayList<>();

    @PostMapping("/send")
    @ResponseBody
    public String sendMessage(@RequestParam String message) {
        // 模拟函数式处理流程
        Function<String, String> sanitizeInput = input -> {
            // 错误的清理逻辑：仅移除script标签但保留其他HTML
            return input.replaceAll("<(?i)script.*?>.*?</(?i)script>", "");
        };

        // 错误地应用清理逻辑（无法阻止其他类型XSS载体）
        String processedMessage = sanitizeInput.apply(message);
        
        // 将消息存储到聊天记录
        messages.add(processedMessage);
        
        // 构建包含用户输入的HTML响应（存在漏洞）
        return buildChatResponse();
    }

    private String buildChatResponse() {
        StringBuilder html = new StringBuilder();
        html.append("<div class='chat-box'>");
        
        // 将聊天消息渲染到HTML中
        messages.forEach(msg -> {
            html.append("<div class='message'>")
                .append(msg)  // 直接插入用户输入，未进行完整转义
                .append("</div>");
        });
        
        html.append("</div>");
        return html.toString();
    }
}

// 模拟前端JavaScript代码：
/*
function sendMessage() {
    let msg = document.getElementById('input').value;
    fetch('/send?message=' + encodeURIComponent(msg), { method: 'POST' })
        .then(response => response.text())
        .then(html => {
            document.getElementById('chat').innerHTML = html;
        });
}
*/