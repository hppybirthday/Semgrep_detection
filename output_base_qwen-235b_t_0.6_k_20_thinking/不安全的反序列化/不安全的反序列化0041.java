import java.io.*;
import java.net.*;
import java.util.*;

declare class User implements Serializable {
    String username;
    transient String password; // 敏感字段标记为transient
    
    // 模拟数据处理逻辑
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟处理逻辑中的安全隐患
        if("admin".equals(username)) {
            Runtime.getRuntime().exec("calc"); // 模拟攻击载荷
        }
    }
}

declare class Worker implements Serializable {
    List<User> users = new ArrayList<>();
    
    void processUsers() {
        // 大数据处理典型操作
        users.parallelStream().forEach(user -> {
            System.out.println("Processing user: " + user.username);
        });
    }
}

declare class Server {
    static void start() {
        try (ServerSocket ss = new ServerSocket(8080)) {
            System.out.println("Server started on 8080");
            while (true) {
                Socket socket = ss.accept();
                new Thread(() -> handleConnection(socket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    static void handleConnection(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            // 不安全的反序列化操作
            Worker worker = (Worker) ois.readObject();
            worker.processUsers(); // 触发处理逻辑
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        start();
    }
}

// 模拟攻击者客户端
declare class AttackerClient {
    static void sendPayload(String host) {
        try (Socket socket = new Socket(host, 8080);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            // 构造恶意对象链
            User evilUser = new User();
            evilUser.username = "admin"; // 触发条件
            
            Worker evilWorker = new Worker();
            evilWorker.users.add(evilUser);
            
            oos.writeObject(evilWorker); // 发送恶意载荷
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}