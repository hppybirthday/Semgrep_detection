import java.io.*;
import java.util.Base64;

// 模拟聊天消息类
class ChatMessage implements Serializable {
    private String content;
    public ChatMessage(String content) { this.content = content; }
    public String getContent() { return content; }
}

// 模拟聊天服务器
public class ChatServer {
    // 模拟处理客户端消息（存在漏洞的反序列化）
    public void processMessage(String encodedData) {
        try {
            // 危险操作：直接反序列化Base64数据
            byte[] data = Base64.getDecoder().decode(encodedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            ChatMessage msg = (ChatMessage) ois.readObject();
            System.out.println("Received: " + msg.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 模拟客户端发送消息
    public static String simulateClientMessage(Object obj) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(obj);
            oos.flush();
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        ChatServer server = new ChatServer();
        
        // 正常消息示例
        System.out.println("Normal message test:");
        String normalMsg = simulateClientMessage(new ChatMessage("Hello World"));
        server.processMessage(normalMsg);
        
        // 恶意payload示例（假设攻击者构造的恶意对象）
        System.out.println("\
Malicious payload test:");
        // 实际攻击中可能包含CommonsCollections等gadget链
        String maliciousPayload = "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eLndhsmQYcMAA1QAAWV4cAAAAA==";
        server.processMessage(maliciousPayload);
    }
}