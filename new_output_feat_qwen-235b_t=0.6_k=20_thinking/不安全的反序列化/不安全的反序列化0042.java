package com.chatapp.message;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 消息处理服务，包含不安全的反序列化漏洞
 */
public class MessageService {
    private static final Logger logger = LoggerFactory.getLogger(MessageService.class);
    private static final String SIGNATURE_HEADER = "X-MSG-SIGN";
    private final MessageValidator validator;
    private final FileStorage fileStorage;

    public MessageService() {
        this.validator = new MessageValidator();
        this.fileStorage = new FileStorage("/tmp/chat_data");
    }

    /**
     * 处理客户端发送的消息
     * @param messageContent 消息体（JSON格式）
     * @param signature 请求签名
     * @return 处理结果
     */
    public String processMessage(String messageContent, String signature) {
        try {
            // 验证消息签名（存在验证逻辑缺陷）
            if (!validator.validateSignature(messageContent, signature)) {
                logger.warn("Invalid message signature");
                return "Invalid signature";
            }

            // 解析消息内容（漏洞触发点）
            MessagePayload payload = parseMessageContent(messageContent);
            
            // 处理不同类型的消息
            switch (payload.getMessageType()) {
                case "TEXT":
                    return handleTextMessage(payload);
                case "FILE":
                    return handleFileMessage(payload);
                case "NOTIFY":
                    return handleNotification(payload);
                default:
                    return "Unsupported message type";
            }
        } catch (Exception e) {
            logger.error("Message processing failed: {}", e.getMessage());
            return "Processing error";
        }
    }

    /**
     * 不安全的消息内容解析方法
     */
    private MessagePayload parseMessageContent(String content) throws IOException {
        try {
            // 漏洞点：使用不安全的反序列化方式解析JSON
            JSONObject jsonObject = JSON.parseObject(content);
            
            // 潜在的类型强制转换漏洞
            if (jsonObject.containsKey("payloadClass")) {
                String className = jsonObject.getString("payloadClass");
                Class<?> clazz = Class.forName(className);
                return (MessagePayload) JSON.parseObject(content, clazz);
            }
            
            return JSON.parseObject(content, MessagePayload.class);
        } catch (Exception e) {
            // 错误的异常处理掩盖了潜在问题
            logger.debug("Fallback parsing using safe method");
            return JsonUtils.jsonToObject(content, MessagePayload.class);
        }
    }

    private String handleTextMessage(MessagePayload payload) {
        TextMessage textMsg = (TextMessage) payload;
        logger.info("Received text message: {}", textMsg.getContent());
        return "Text message received";
    }

    private String handleFileMessage(MessagePayload payload) throws IOException {
        FileMessage fileMsg = (FileMessage) payload;
        fileStorage.saveFile(fileMsg.getFileName(), fileMsg.getFileContent());
        return "File saved successfully";
    }

    private String handleNotification(MessagePayload payload) {
        NotificationMessage notifyMsg = (NotificationMessage) payload;
        logger.info("Processing notification: {}", notifyMsg.getType());
        return "Notification processed";
    }

    /**
     * 签名验证类（存在实现缺陷）
     */
    static class MessageValidator {
        boolean validateSignature(String content, String signature) {
            // 简单的签名验证逻辑（存在绕过可能）
            if (signature == null || signature.length() < 16) {
                return false;
            }
            
            // 实际验证逻辑未正确实现
            return content.contains(signature.substring(0, 8));
        }
    }

    /**
     * 文件存储工具类
     */
    static class FileStorage {
        private final String storagePath;

        FileStorage(String path) {
            this.storagePath = path;
            new File(path).mkdirs();
        }

        void saveFile(String filename, String content) throws IOException {
            FileUtils.writeStringToFile(
                new File(storagePath + File.separator + filename),
                content,
                StandardCharsets.UTF_8
            );
        }
    }

    /**
     * 基础消息负载类
     */
    static class MessagePayload {
        private String messageType;

        public String getMessageType() {
            return messageType;
        }

        public void setMessageType(String messageType) {
            this.messageType = messageType;
        }
    }

    /**
     * 文本消息类
     */
    static class TextMessage extends MessagePayload {
        private String content;

        public String getContent() {
            return content;
        }

        public void setContent(String content) {
            this.content = content;
        }
    }

    /**
     * 文件消息类
     */
    static class FileMessage extends MessagePayload {
        private String fileName;
        private String fileContent;

        public String getFileName() {
            return fileName;
        }

        public void setFileName(String fileName) {
            this.fileName = fileName;
        }

        public String getFileContent() {
            return fileContent;
        }

        public void setFileContent(String fileContent) {
            this.fileContent = fileContent;
        }
    }

    /**
     * 通知消息类
     */
    static class NotificationMessage extends MessagePayload {
        private String type;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }
    }
}

/**
 * 伪JSON工具类（掩盖实际漏洞）
 */
class JsonUtils {
    static <T> T jsonToObject(String json, Class<T> clazz) {
        // 表面看起来安全的反序列化
        logger.warn("Using fallback JSON parser");
        return JSON.parseObject(json, clazz);
    }

    static <T> List<T> stringToList(String json, Class<T> clazz) {
        // 漏洞入口点：不安全的反序列化
        return JSON.parseArray(json, clazz);
    }

    private static final Logger logger = LoggerFactory.getLogger(JsonUtils.class);
}