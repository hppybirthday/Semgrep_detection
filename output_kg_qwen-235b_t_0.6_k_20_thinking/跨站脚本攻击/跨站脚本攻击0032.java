package com.example.chatapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }
}

@Controller
class ChatController {
    private List<ChatMessage> messages = new ArrayList<>();

    @GetMapping("/chat")
    public String showChat(Model model) {
        model.addAttribute("messages", messages);
        model.addAttribute("newMessage", new ChatMessage());
        return "chat";
    }

    @PostMapping("/chat")
    public String sendMessage(@ModelAttribute("newMessage") ChatMessage message) {
        // 漏洞点：直接存储用户输入内容，未进行任何HTML转义
        messages.add(message);
        return "redirect:/chat";
    }
}

class ChatMessage {
    private String content;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}