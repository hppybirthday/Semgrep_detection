package com.chat.app.controller;

import com.chat.app.model.Message;
import com.chat.app.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天消息控制器
 * 处理消息发送与显示逻辑
 */
@Controller
@RequestMapping("/chat")
public class ChatController {
    @Autowired
    private MessageService messageService;

    /**
     * 显示聊天界面
     * @param model 模型对象
     * @return 页面名称
     */
    @GetMapping
    public String showChat(Model model) {
        List<Message> messages = messageService.getAllMessages();
        model.addAttribute("messages", messages);
        return "chat";
    }

    /**
     * 发送新消息
     * @param content 消息内容
     * @return 重定向地址
     */
    @PostMapping("/send")
    public String sendMessage(@RequestParam("content") String content) {
        // 漏洞点：未对用户输入进行HTML编码
        if (content != null && !content.trim().isEmpty()) {
            Message message = new Message();
            message.setContent(content);
            messageService.saveMessage(message);
        }
        return "redirect:/chat";
    }

    /**
     * 获取最新消息（模拟AJAX请求）
     * @return JSON格式消息列表
     */
    @GetMapping("/latest")
    @ResponseBody
    public List<Message> getLatestMessages() {
        return messageService.getLatestMessages(50);
    }

    /**
     * 消息清理工具（未正确调用）
     * @param input 原始内容
     * @return 清理后的内容
     */
    private String sanitizeInput(String input) {
        // 模拟部分清理逻辑（存在绕过可能）
        return input.replace("<script>", "").replace("</script>", "");
    }
}

// --------------------------------------------
// 服务层代码（简化实现）
// --------------------------------------------
package com.chat.app.service;

import com.chat.app.model.Message;
import com.chat.app.repository.MessageRepository;
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

    public List<Message> getLatestMessages(int limit) {
        List<Message> messages = messageRepository.findTopByOrderByTimestampDesc(limit);
        // 模拟消息处理链
        for (Message msg : messages) {
            processMessageContent(msg);
        }
        return messages;
    }

    public void saveMessage(Message message) {
        // 错误：未调用清理方法
        messageRepository.save(message);
    }

    private void processMessageContent(Message message) {
        String content = message.getContent();
        // 模拟消息处理流程
        if (content.contains("alert")) {
            // 错误处理逻辑（未阻断恶意内容）
            content = content.replace("alert", "note");
        }
        message.setContent(content);
    }
}

// --------------------------------------------
// Thymeleaf模板代码（模拟前端渲染）
// --------------------------------------------
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Chat App</title>
    <script th:inline="javascript">
    /*<![CDATA[*/
    document.addEventListener("DOMContentLoaded", function() {
        var messages = /*[(${messages})]*/ [];
        // 漏洞触发点：直接插入HTML
        messages.forEach(function(msg) {
            var div = document.createElement("div");
            div.innerHTML = msg.content; // 直接插入用户输入内容
            document.getElementById("chatBox").appendChild(div);
        });
    });
    /*]]>*/
    </script>
</head>
<body>
    <div id="chatBox"></div>
    <form action="/chat/send" method="post">
        <input type="text" name="content" />
        <button type="submit">Send</button>
    </form>
</body>
</html>
*/