package com.example.chatapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }
}

@Entity
class Message {
    @Id
    @GeneratedValue
    private Long id;
    private String content;
    private String username = "anonymous";
    // Getters and setters
}

interface MessageRepository extends JpaRepository<Message, Long> {}

@Service
class ChatService {
    private final MessageRepository messageRepo;
    private final JavaMailSender mailSender;

    public ChatService(MessageRepository messageRepo, JavaMailSender mailSender) {
        this.messageRepo = messageRepo;
        this.mailSender = mailSender;
    }

    public List<Message> getAllMessages() {
        return messageRepo.findAll();
    }

    public void sendMessage(String content, String username) {
        Message msg = new Message();
        msg.setContent(content); // Vulnerable: Raw content storage
        msg.setUsername(username);
        messageRepo.save(msg);
        
        // Vulnerable: Direct content injection into email HTML
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo("recipient@example.com");
            helper.setSubject("New Message from " + username);
            helper.setText("<div class='content'>" + content + "</div>", true); // XSS via HTML email
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}

@Controller
class ChatController {
    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @GetMapping("/")
    public String getChat(Model model) {
        model.addAttribute("messages", chatService.getAllMessages());
        return "index";
    }

    @PostMapping("/send")
    public String postMessage(@RequestParam String content, @RequestParam String username) {
        chatService.sendMessage(content, username);
        return "redirect:/";
    }
}

// Thymeleaf template (resources/templates/index.html)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <div th:each="msg : ${messages}">
//     <b th:text="${msg.username}"></b>: 
//     <span th:utext="${msg.content}"></span> <!-- Vulnerable: Unescaped content rendering -->
//   </div>
//   <form action="/send" method="post">
//     <input name="username" placeholder="Name">
//     <input name="content" placeholder="Message">
//     <button type="submit">Send</button>
//   </form>
// </body>
// </html>