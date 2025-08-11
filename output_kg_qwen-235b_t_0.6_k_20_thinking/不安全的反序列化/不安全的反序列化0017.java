import java.io.*;
import java.net.*;
import java.util.*;

class ChatMessage implements Serializable {
    String user;
    String content;
    
    public ChatMessage(String u, String c) {
        user = u;
        content = c;
    }
}

public class ChatServer {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8888);
        System.out.println("Server started");
        
        while(true) {
            Socket s = ss.accept();
            new Thread(() -> {
                try {
                    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
                    ChatMessage msg = (ChatMessage) ois.readObject();
                    System.out.println("Received: " + msg.user + ": " + msg.content);
                    ois.close();
                    s.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
}

// 恶意客户端示例（攻击者代码）
class EvilClient {
    public static void main(String[] args) throws Exception {
        Socket s = new Socket("127.0.0.1", 8888);
        ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
        // 正常消息示例
        // oos.writeObject(new ChatMessage("test", "hello"));
        // 攻击载荷示例（需要结合具体gadget链）
        // oos.writeObject(恶意对象);
        oos.close();
        s.close();
    }
}