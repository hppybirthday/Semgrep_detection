package com.example.chatapp.controller;

import com.example.chatapp.model.ChatMessage;
import com.example.chatapp.service.ChatService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * 聊天消息处理控制器
 * 提供消息提交和展示功能
 */
@Controller
public class ChatController {
    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    /**
     * 展示聊天界面
     */
    @GetMapping("/chat")
    public String showChat(Model model) {
        List<ChatMessage> messages = chatService.getAllMessages();
        model.addAttribute("messages", messages);
        return "chat_template";
    }

    /**
     * 处理消息提交
     * @param content 消息内容
     * @param username 用户名
     */
    @PostMapping("/chat/send")
    public String processMessage(@RequestParam String content, 
                                @RequestParam String username) {
        // 创建消息对象并处理内容
        ChatMessage message = new ChatMessage();
        message.setContent(formatMessageContent(content));
        message.setUsername(username);

        chatService.saveMessage(message);
        return "redirect:/chat";
    }

    /**
     * 格式化消息内容
     * @param content 原始内容
     * @return 处理后的内容
     */
    private String formatMessageContent(String content) {
        // 添加自动链接功能
        return content.replaceAll("(https?://\\\\S+)", 
                "<a href=\\"$1\\">$1</a>");
    }
}