import java.io.*;
import java.net.*;
import java.util.*;

class ChatMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private String content;
    private String type; // login, message, logout

    public ChatMessage(String username, String content, String type) {
        this.username = username;
        this.content = content;
        this.type = type;
    }

    public String getUsername() { return username; }
    public String getContent() { return content; }
    public String getType() { return type; }
}

public class ChatServer {
    private static final Map<String, PrintWriter> clients = new HashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(9000)) {
            System.out.println("Server started on port 9000");
            while (true) {
                new ClientHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler extends Thread {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

                Object obj = ois.readObject(); // 不安全的反序列化
                if (obj instanceof ChatMessage) {
                    ChatMessage message = (ChatMessage) obj;
                    if ("login".equals(message.getType())) {
                        handleLogin(message, oos);
                    }
                }

                while (true) {
                    Object received = ois.readObject(); // 持续反序列化
                    if (received instanceof ChatMessage) {
                        broadcast((ChatMessage) received);
                    }
                }
            } catch (IOException | ClassNotFoundException e) {
                System.err.println("Client error: " + e.getMessage());
            } finally {
                try { socket.close(); } catch (IOException e) {}
            }
        }

        private void handleLogin(ChatMessage message, ObjectOutputStream oos) {
            clients.put(message.getUsername(), new PrintWriter(oos));
            System.out.println(message.getUsername() + " joined");
            broadcast(new ChatMessage("SERVER", message.getUsername() + " has entered the chat", "message"));
        }

        private void broadcast(ChatMessage message) {
            System.out.println("Broadcasting: " + message.getContent());
            clients.values().forEach(writer -> {
                try {
                    writer.writeObject(message);
                    writer.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

// 恶意客户端示例（攻击者代码）
class EvilClient {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("localhost", 9000)) {
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            // 发送恶意序列化对象
            oos.writeObject(createEvilObject());
        }
    }

    // 模拟攻击者构造的恶意对象
    static Object createEvilObject() {
        // 实际攻击可能使用反序列化gadget执行任意代码
        // 这里简化为触发异常的恶意对象
        return new ChatMessage("hacker", "malicious payload", "invalid_type");
    }
}