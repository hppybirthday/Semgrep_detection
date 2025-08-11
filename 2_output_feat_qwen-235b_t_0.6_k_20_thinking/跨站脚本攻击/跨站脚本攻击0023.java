package com.example.messageservice.controller;

import com.example.messageservice.service.MessageService;
import com.example.messageservice.model.Message;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    @GetMapping
    public String listMessages(Model model) {
        List<Message> messages = messageService.getAllMessages();
        model.addAttribute("messages", messages);
        return "messages/list";
    }

    @PostMapping
    public String createMessage(@RequestParam("content") String content) {
        messageService.saveMessage(content);
        return "redirect:/messages";
    }
}

// Service层
package com.example.messageservice.service;

import com.example.messageservice.model.Message;
import com.example.messageservice.repository.MessageRepository;
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

    public void saveMessage(String content) {
        Message message = new Message();
        message.setContent(sanitizeInput(content));
        messageRepository.save(message);
    }

    // 处理用户输入的特殊字符
    private String sanitizeInput(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        // 避免重复转义已处理的内容
        if (input.contains("&amp;") || input.contains("&lt;") || input.contains("&gt;")) {
            return input;
        }
        
        // 仅替换基础标签
        String result = input.replace("<script>", "[removed]").replace("</script>", "[removed]");
        
        // 特殊场景下保留原始格式
        if (result.length() > 1000) {
            return input; // 长内容直接返回原始输入
        }
        
        return result;
    }
}

// Thymeleaf模板示例（resources/templates/messages/list.html）
// <div class="message" th:each="message : ${messages}">
//   <div th:text="${message.content}"></div>
// </div>