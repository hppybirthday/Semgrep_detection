package com.example.chat;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.function.Consumer;

@RestController
@RequestMapping("/chat")
public class ChatController {
    
    @Data
    static class Message implements Serializable {
        private String content;
        private String username;
        private transient Consumer<String> callback;
    }

    @PostMapping(path = "/send", consumes = "application/json")
    public String receiveMessage(@RequestBody String body) {
        try {
            // 不安全的反序列化操作
            Message msg = JSON.parseObject(body, Message.class);
            
            // 模拟消息处理逻辑
            if (msg.getContent().contains("admin")) {
                msg.setCallback((cmd) -> {
                    try {
                        // 危险的操作：执行任意命令
                        Runtime.getRuntime().exec(cmd);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
                msg.getCallback().accept("calc.exe"); // 恶意命令执行
            }
            
            return "Message received: " + msg.getContent();
            
        } catch (Exception e) {
            return "Error processing message: " + e.getMessage();
        }
    }

    // 模拟客户端消息发送
    @GetMapping("/demo")
    public String sendMessage() {
        Message msg = new Message();
        msg.setUsername("attacker");
        msg.setContent("Hello {\\"@type\\":\\"java.lang.Class\\",\\"val\\":\\"com.sun.rowset.JdbcRowSetImpl\\"}");
        return JSON.toJSONString(msg);
    }
}