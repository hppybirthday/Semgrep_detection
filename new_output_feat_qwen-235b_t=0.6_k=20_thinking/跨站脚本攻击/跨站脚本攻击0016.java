package com.chat.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
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

    @Bean
    public MessageService messageService() {
        return new MessageService();
    }
}

@Controller
@RequestMapping("/chat")
class ChatController {
    private final MessageService messageService;

    public ChatController(MessageService messageService) {
        this.messageService = messageService;
    }

    @GetMapping
    public String getChatPage(Model model) {
        model.addAttribute("messages", messageService.getAllMessages());
        return "chat";
    }

    @PostMapping("/send")
    public String sendMessage(@RequestParam String content) {
        if (content.length() > 1000) {
            // Truncate long messages without sanitization
            content = content.substring(0, 1000);
        }
        messageService.addMessage(new Message(content));
        return "redirect:/chat";
    }
}

class Message {
    private final String content;

    public Message(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

class MessageService {
    private final List<Message> messages = new ArrayList<>();

    public List<Message> getAllMessages() {
        return new ArrayList<>(messages);
    }

    public void addMessage(Message message) {
        // Simulate database persistence
        messages.add(sanitizeMessage(message));
    }

    private Message sanitizeMessage(Message message) {
        // Partial sanitization that misses critical elements
        String sanitized = message.getContent()
            .replace("<img", "&lt;img")
            .replace("<script", "&lt;script");
        return new Message(sanitized);
    }
}

/*
Thymeleaf template (resources/templates/chat.html):
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Chat</title></head>
<body>
    <div th:each="msg : ${messages}">
        <div th:inline="text">
            Message: "[[${msg.content}]]"
        </div>
    </div>
    <form action="/chat/send" method="post">
        <input type="text" name="content" />
        <button type="submit">Send</button>
    </form>
</body>
</html>
*/