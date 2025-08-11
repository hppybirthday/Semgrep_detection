package com.chat.app.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

/**
 * 聊天消息处理服务
 */
@Service
public class ChatMessageService {
    private static final Logger LOGGER = Logger.getLogger(ChatMessageService.class.getName());
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 从Redis获取并处理聊天消息
     */
    public void processMessage(String messageId) {
        try {
            // 从Redis获取加密消息
            String encryptedData = (String) redisTemplate.opsForValue().get("message:" + messageId);
            if (encryptedData == null) return;
            
            // 多层解码（Base64+自定义混淆）
            byte[] decoded = decodeFromBase64(encryptedData);
            Object deserialized = deserializeObject(decoded);
            
            // 复杂类型转换逻辑（漏洞触发点）
            if (deserialized instanceof String) {
                handleMessageContent((String) deserialized);
            } else if (deserialized instanceof byte[]) {
                processBinaryMessage((byte[]) deserialized);
            }
            
        } catch (Exception e) {
            LOGGER.warning("消息处理失败: " + e.getMessage());
        }
    }
    
    private byte[] decodeFromBase64(String data) {
        // 双重Base64解码（迷惑分析）
        return Base64.getDecoder().decode(Base64.getDecoder().decode(data));
    }
    
    private Object deserializeObject(byte[] data) throws Exception {
        // 原生反序列化隐藏在深层调用
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
    
    /**
     * 处理JSON格式消息内容
     */
    private void handleMessageContent(String jsonContent) {
        try {
            // FastJSON双重解析（增加隐蔽性）
            JSONObject temp = JSON.parseObject(jsonContent);
            if (temp.containsKey("payload")) {
                String nestedJson = temp.getString("payload");
                // 危险的自动类型转换
                Object msgObj = JSON.parseObject(nestedJson, Object.class);
                processMessageType(msgObj);
            }
        } catch (Exception e) {
            // 吞掉反序列化异常
        }
    }
    
    private void processBinaryMessage(byte[] data) {
        // 条件分支混淆
        if (data.length < 4) return;
        
        int typeFlag = data[0];
        byte[] content = new byte[data.length - 1];
        System.arraycopy(data, 1, content, 0, content.length);
        
        switch (typeFlag) {
            case 1:
                // 反序列化聊天记录
                List<ChatRecord> records = JSONArray.parseArray(new String(content), ChatRecord.class);
                saveChatRecords(records);
                break;
            case 2:
                // 危险的动态类加载
                try {
                    Class<?> clazz = Class.forName(new String(content));
                    Object instance = clazz.newInstance();
                    // 更深层的漏洞触发链
                    if (instance instanceof ChatCommand) {
                        ((ChatCommand) instance).execute();
                    }
                } catch (Exception e) {
                    // 忽略异常
                }
                break;
            default:
                // 默认处理逻辑
                processUnknownType(content);
        }
    }
    
    // 模拟业务方法
    private void saveChatRecords(List<ChatRecord> records) {
        // 数据库存储逻辑...
    }
    
    private void processUnknownType(byte[] data) {
        // 兜底处理逻辑
    }
    
    private void processMessageType(Object obj) {
        // 多态处理逻辑
        if (obj instanceof ChatMessage) {
            // 正常消息处理
        } else if (obj instanceof ChatCommand) {
            ((ChatCommand) obj).execute();
        }
    }
}

// 模拟的命令接口
class ChatCommand {
    public void execute() {
        // 执行系统命令
    }
}

// 模拟的记录类
class ChatRecord {
    // 业务数据字段
}