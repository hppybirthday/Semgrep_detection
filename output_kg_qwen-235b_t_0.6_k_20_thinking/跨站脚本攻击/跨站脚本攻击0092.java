package com.example.xsschat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

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
    private final List<String> messages = new ArrayList<>();

    @GetMapping("/chat")
    public String chat(@RequestParam String message, Model model) {
        if (message != null && !message.isEmpty()) {
            messages.add(message);
        }
        model.addAttribute("messages", messages);
        return "chat";
    }
}

// templates/chat.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Chat</title></head>
// <body>
// <div th:each="msg : ${messages}">
//     <div th:text="${msg}"></div>
// </div>
// <form action="/chat">
//     <input type="text" name="message">
//     <button type="submit">Send</button>
// </form>
// </body>
// </html>