package com.example.chat;

import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.engine.PageQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/messages")
public class ChatController {
    @Autowired
    private ChatService chatService;

    @GetMapping
    public List<ChatMessage> getMessages(@RequestParam String userId, 
                                         @RequestParam(required = false) String orderBy) {
        return chatService.getChatHistory(userId, orderBy);
    }
}

class ChatService {
    @Autowired
    private ChatMapper chatMapper;

    public List<ChatMessage> getChatHistory(String userId, String orderBy) {
        return chatMapper.queryMessages(userId, orderBy);
    }
}

interface ChatMapper {
    SQLManager sqlManager;

    default List<ChatMessage> queryMessages(String userId, String orderBy) {
        String querySQL = "SELECT * FROM chat_messages WHERE user_id = '" + userId + "'";
        if (orderBy != null && !orderBy.isEmpty()) {
            querySQL += " ORDER BY " + orderBy; // 漏洞点：直接拼接排序参数
        }
        return sqlManager.execute(querySQL, ChatMessage.class);
    }
}

class ChatMessage {
    private String id;
    private String userId;
    private String content;
    private long timestamp;
    // getters and setters
}

/*
攻击示例：
GET /messages?userId=admin&orderBy=1;DROP TABLE chat_messages-- 
生成的SQL:
SELECT * FROM chat_messages WHERE user_id = 'admin' ORDER BY 1;DROP TABLE chat_messages-- 
*/