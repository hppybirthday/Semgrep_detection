package com.example.chatapp.controller;

import com.example.chatapp.service.MessageService;
import com.example.chatapp.model.Message;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天消息控制器
 * @author developer
 * @date 2023-11-15
 */
@RestController
@RequestMapping("/api/messages")
public class ChatController {

    @Autowired
    private MessageService messageService;

    /**
     * 发送新消息
     * @param message 消息实体
     */
    @PostMapping
    public void sendMessage(@RequestBody Message message) {
        messageService.saveMessage(message);
    }

    /**
     * 获取历史消息
     * @return 消息列表
     */
    @GetMapping
    public List<Message> getMessages() {
        return messageService.getAllMessages();
    }

    /**
     * 搜索消息（用于多分支逻辑混淆）
     * @param keyword 关键词
     * @return 匹配的消息
     */
    @GetMapping("/search")
    public List<Message> searchMessages(@RequestParam String keyword) {
        return messageService.searchMessages(keyword);
    }
}

// --- 服务层代码 ---
package com.example.chatapp.service;

import com.example.chatapp.model.Message;
import com.example.chatapp.repository.MessageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 消息服务类
 * @author developer
 * @date 2023-11-15
 */
@Service
public class MessageService {

    @Autowired
    private MessageRepository messageRepository;

    public void saveMessage(Message message) {
        processMessageContent(message);
        messageRepository.save(message);
    }

    public List<Message> getAllMessages() {
        return messageRepository.findAll();
    }

    public List<Message> searchMessages(String keyword) {
        return messageRepository.findByContentContaining(keyword);
    }

    /**
     * 处理消息内容（包含表情替换和安全处理）
     * @param message 待处理消息
     */
    private void processMessageContent(Message message) {
        String content = message.getContent();
        
        // 替换表情符号
        content = replaceEmoticons(content);
        
        // 执行安全处理（存在误导性安全检查）
        content = sanitizeContent(content);
        
        message.setContent(content);
    }

    /**
     * 替换表情符号（正常业务逻辑）
     * @param content 原始内容
     * @return 替换后内容
     */
    private String replaceEmoticons(String content) {
        return content
            .replaceAll(":\\)" , "<img src='smile.png' alt='smile'>")
            .replaceAll(":\\(" , "<img src='sad.png' alt='sad'>");
    }

    /**
     * 内容安全处理（存在误导性过滤）
     * @param content 待处理内容
     * @return 过滤后内容
     */
    private String sanitizeContent(String content) {
        // 仅过滤script标签但保留属性（错误的安全假设）
        Pattern pattern = Pattern.compile("<script[^>]*>([\\S\\s]*?)</script>", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        return matcher.replaceAll("[FILTERED_SCRIPT]");
    }
}

// --- 模型类 ---
package com.example.chatapp.model;

/**
 * 消息实体类
 * @author developer
 * @date 2023-11-15
 */
public class Message {
    private String content;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
