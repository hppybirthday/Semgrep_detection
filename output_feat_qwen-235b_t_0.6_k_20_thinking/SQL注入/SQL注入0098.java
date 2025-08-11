package com.chat.example;

import org.springframework.web.bind.annotation.*;
import com.github.pagehelper.PageHelper;
import java.util.List;

@RestController
@RequestMapping("/messages")
public class ChatController {
    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @GetMapping
    public List<Message> getMessages(@RequestParam String sort, @RequestParam String order) {
        PageHelper.orderBy(sort + " " + order);
        return chatService.getAllMessages();
    }
}

@Service
class ChatService {
    private final MessageMapper messageMapper;

    public ChatService(MessageMapper messageMapper) {
        this.messageMapper = messageMapper;
    }

    public List<Message> getAllMessages() {
        return messageMapper.selectAll();
    }
}

@Mapper
interface MessageMapper {
    @Select("SELECT * FROM messages ORDER BY id DESC")
    List<Message> selectAll();
}

class Message {
    private Long id;
    private String content;
    private String username;
    // Getters and setters
}

// MyBatisConfig.java (simplified)
@Configuration
@MapperScan("com.chat.example")
public class MyBatisConfig {
    // Database connection config
}

// PageHelper usage in config
@Bean
public PageInterceptor pageInterceptor() {
    return new PageInterceptor();
}