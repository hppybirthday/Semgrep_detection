import java.io.*;
import java.net.*;
import java.util.function.*;
import java.util.concurrent.*;

public class ChatServer {
    private static final int PORT = 8080;
    private static final ExecutorService pool = Executors.newCachedThreadPool();

    static class ChatMessage implements Serializable {
        private String content;
        public ChatMessage(String content) { this.content = content; }
        public String getContent() { return content; }
    }

    static class MessageHandler implements Runnable {
        private final ObjectInputStream in;
        
        public MessageHandler(InputStream socketIn) throws IOException {
            this.in = new ObjectInputStream(socketIn);
        }

        @Override
        public void run() {
            try {
                // 不安全的反序列化操作
                Object obj = in.readObject();
                if (obj instanceof ChatMessage) {
                    System.out.println("Received: " + ((ChatMessage)obj).getContent());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);
            
            // 函数式编程风格处理客户端连接
            Consumer<Socket> handler = socket -> {
                try {
                    System.out.println("Client connected: " + socket.getInetAddress());
                    pool.execute(new MessageHandler(socket.getInputStream()));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            };

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handler.accept(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            pool.shutdown();
        }
    }
}

// 恶意客户端示例（攻击者实现）
class EvilClient {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", 8080)) {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            
            // 构造恶意序列化数据（示例）
            // 实际攻击中可能包含命令执行payload
            Object payload = createEvilObject();
            out.writeObject(payload);
            out.flush();
        }
    }

    // 模拟恶意对象构造（需要具体gadget链）
    private static Object createEvilObject() {
        // 真实攻击中可能使用Commons-Collections等库的gadget链
        return new Object(); // 占位符
    }
}