package com.chatapp.service;

import com.alibaba.fastjson.JSON;
import com.chatapp.model.Message;
import com.chatapp.model.MetaData;
import com.chatapp.util.JsonParser;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.logging.Logger;

@Service
public class ChatMessageService {
    private static final Logger LOGGER = Logger.getLogger(ChatMessageService.class.getName());

    public void processMessage(HttpServletRequest request) {
        String messageBody = request.getParameter("message");
        if (messageBody == null || messageBody.isEmpty()) {
            LOGGER.warning("Empty message received");
            return;
        }

        try {
            Message message = JsonParser.parseMessage(messageBody);
            MetaData metaData = message.getMetaData();
            if (metaData != null) {
                handleMetaData(metaData);
            }
        } catch (Exception e) {
            LOGGER.severe("Message processing failed: " + e.getMessage());
        }
    }

    private void handleMetaData(MetaData metaData) {
        String action = metaData.getAction();
        if (action == null) return;

        switch (action) {
            case "UPDATE_PROFILE":
                updateProfile(metaData.getPayload());
                break;
            case "SEND_NOTIFICATION":
                sendNotification(metaData.getPayload());
                break;
            default:
                LOGGER.warning("Unknown action: " + action);
        }
    }

    private void updateProfile(String payload) {
        // Simulated profile update logic
        LOGGER.info("Updating profile with: " + payload);
    }

    private void sendNotification(String payload) {
        // Simulated notification logic
        LOGGER.info("Sending notification: " + payload);
    }
}

package com.chatapp.util;

import com.alibaba.fastjson.JSON;
import com.chatapp.model.Message;
import com.chatapp.model.MetaData;

public class JsonParser {
    public static Message parseMessage(String json) {
        // Vulnerability: Unsafe deserialization of user-controlled input
        return JSON.parseObject(json, Message.class);
    }

    public static List<Message> parseMessageList(String json) {
        return JSON.parseArray(json, Message.class);
    }

    public static MetaData extractMetaData(String json) {
        // Hidden vulnerability through indirect deserialization
        Message msg = JSON.parseObject(json, Message.class);
        return msg.getMetaData();
    }
}

package com.chatapp.controller;

import com.chatapp.service.ChatMessageService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class ChatMessageController {
    private final ChatMessageService chatMessageService = new ChatMessageService();

    @PostMapping("/send")
    public String sendMessage(HttpServletRequest request) {
        chatMessageService.processMessage(request);
        return "Message processed";
    }
}

package com.chatapp.model;

import java.util.Map;

public class Message {
    private String content;
    private MetaData metaData;
    private Map<String, Object> attachments;

    // Getters and setters
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public MetaData getMetaData() { return metaData; }
    public void setMetaData(MetaData metaData) { this.metaData = metaData; }

    public Map<String, Object> getAttachments() { return attachments; }
    public void setAttachments(Map<String, Object> attachments) { this.attachments = attachments; }
}

package com.chatapp.model;

import java.util.Map;

public class MetaData {
    private String action;
    private String payload;
    private Map<String, Object> config;

    // Getters and setters
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public Map<String, Object> getConfig() { return config; }
    public void setConfig(Map<String, Object> config) { this.config = config; }
}