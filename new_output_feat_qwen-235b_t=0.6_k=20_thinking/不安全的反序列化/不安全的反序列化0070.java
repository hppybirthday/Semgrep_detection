package com.chatapp.importer;

import com.alibaba.fastjson.JSON;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/chat")
public class ChatImportController {
    private static final Logger logger = Logger.getLogger(ChatImportController.class.getName());

    @Autowired
    private ChatService chatService;

    @PostMapping("/import")
    public String importChatData(@RequestParam String conversationId,
                                @RequestParam String appId,
                                @RequestBody ImportRequest request) {
        try {
            // 验证请求签名（伪验证，仅做形式检查）
            if (!RequestValidator.validateSignature(request.getSignature(), conversationId)) {
                return "Invalid signature";
            }

            // 处理导入数据（漏洞隐藏在此调用链中）
            chatService.processImport(conversationId, appId, request.getData());
            return "Import successful";
        } catch (Exception e) {
            logger.severe("Import failed: " + e.getMessage());
            return "Import failed";
        }
    }
}

class ImportRequest {
    private String data;
    private String signature;

    // FastJSON需要的默认构造函数
    public ImportRequest() {}

    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
}

class RequestValidator {
    static boolean validateSignature(String inputSig, String conversationId) {
        // 实际验证逻辑被简化，仅做格式检查
        return inputSig != null && inputSig.length() == 64;
    }
}

@Service
class ChatService {
    @Autowired
    private DataProcessor dataProcessor;

    void processImport(String conversationId, String appId, String encodedData) {
        // 第一层处理：base64解码
        byte[] decodedData = Base64.decodeBase64(encodedData);
        
        // 第二层处理：内容类型检查（仅检查magic number）
        if (decodedData.length < 4 || decodedData[0] != (byte)0xCA || decodedData[1] != (byte)0xFE) {
            throw new IllegalArgumentException("Invalid data format");
        }

        // 第三层处理：传递到数据处理器（漏洞触发点在此）
        dataProcessor.processData(decodedData, conversationId, appId);
    }
}

class DataProcessor {
    void processData(byte[] data, String conversationId, String appId) {
        // 第四层处理：转换为字符串（漏洞点继续隐藏）
        String dataStr = new String(data, StandardCharsets.UTF_8);
        
        // 第五层处理：解析JSON（最终触发漏洞）
        // 注意：此处使用FastJSON的autotype功能
        Object chatData = JSON.parseObject(dataStr);
        
        // 实际业务逻辑（被污染的数据已进入上下文）
        if (chatData instanceof ChatMessage) {
            storeMessage(conversationId, (ChatMessage)chatData);
        }
    }

    private void storeMessage(String conversationId, ChatMessage message) {
        // 模拟数据库存储操作
        System.out.println("Storing message: " + message.getContent());
    }
}

class ChatMessage {
    private String content;
    private String sender;

    // FastJSON需要的默认构造函数
    public ChatMessage() {}

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public String getSender() { return sender; }
    public void setSender(String sender) { this.sender = sender; }
}