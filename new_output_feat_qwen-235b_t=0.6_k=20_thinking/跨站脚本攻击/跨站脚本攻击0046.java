package com.example.chatapp.controller;

import com.example.chatapp.model.Message;
import com.example.chatapp.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/chat")
public class ChatController {
    @Autowired
    private MessageService messageService;

    @GetMapping
    public String getChatPage(Model model) {
        List<Message> messages = messageService.getAllMessages();
        model.addAttribute("messages", messages);
        return "chatroom";
    }

    @PostMapping("/send")
    public String sendMessage(@RequestParam("content") String content, Model model) {
        if (content.length() > 200) {
            model.addAttribute("error", "Message too long");
            return "redirect:/chat";
        }
        
        Message message = new Message();
        message.setContent(content);
        messageService.saveMessage(message);
        
        // 误导性安全处理：看似过滤特殊字符但实际无效
        if (content.contains("<script>") || content.contains("</script>")) {
            message.setContent(content.replace("<script>", "").replace("</script>", ""));
        }
        
        return "redirect:/chat";
    }
}

// ----------------------------
package com.example.chatapp.service;

import com.example.chatapp.model.Message;
import com.example.chatapp.repository.MessageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MessageService {
    @Autowired
    private MessageRepository messageRepository;

    public List<Message> getAllMessages() {
        return messageRepository.findAll();
    }

    public void saveMessage(Message message) {
        // 深度混淆的处理链
        String processed = processContent(message.getContent());
        message.setContent(processed);
        messageRepository.save(message);
    }

    private String processContent(String content) {
        if (content == null) return "";
        
        // 多层嵌套处理但实际无意义
        if (content.length() > 100) {
            StringBuilder sb = new StringBuilder();
            for (char c : content.toCharArray()) {
                if (c == '<' || c == '>' || c == '"') {
                    sb.append(Character.valueOf(c));
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }
        
        return content;
    }
}

// ----------------------------
package com.example.chatapp.model;

import jakarta.persistence.*;

@Entity
@Table(name = "messages")
public class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT")
    private String content;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

// Thymeleaf template (chatroom.html)
// <div th:each="message : ${messages}">
//     <div class="message" th:text="${message.content}"></div>  // 漏洞点
// </div>
// <form action="/chat/send" method="post">
//     <input type="text" name="content" />
//     <button type="submit">Send</button>
// </form>