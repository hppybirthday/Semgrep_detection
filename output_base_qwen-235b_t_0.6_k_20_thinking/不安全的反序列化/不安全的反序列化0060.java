import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

class User implements Serializable {
    private String username;
    private String role;

    public User(String username, String role) {
        this.username = username;
        this.role = role;
    }

    public void deleteCustomerData() {
        System.out.println("[DANGEROUS] Deleting all customer data...");
        // 实际可能执行数据库删除操作
    }
}

public class CRMSystem {
    static Map<String, String> userSessions = new HashMap<>();

    public static void handleLogin(String username, String password) {
        if ("admin".equals(username) && "securePass123".equals(password)) {
            User user = new User(username, "ADMIN");
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                oos.writeObject(user);
                oos.flush();
                String serializedUser = Base64.getEncoder().encodeToString(bos.toByteArray());
                userSessions.put("session_12345", serializedUser);
                System.out.println("Login successful. Session created.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Login failed");
        }
    }

    public static void handleWelcomeRequest(String sessionId) {
        String serializedUser = userSessions.get(sessionId);
        if (serializedUser != null) {
            try {
                byte[] data = Base64.getDecoder().decode(serializedUser);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                User user = (User) ois.readObject();
                System.out.println("Welcome " + user.getClass().getName());
                
                // 模拟根据角色执行操作
                if (user instanceof User && "ADMIN".equals(user.role)) {
                    user.deleteCustomerData();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        // 模拟正常登录流程
        handleLogin("admin", "securePass123");
        
        // 模拟攻击者修改session数据
        String maliciousSession = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaG1hcAUZa4r0Wq8CAAJGAApsb2FkRmFjdG9ySRALZW50cmllc0NvdW50eHAAAAABAAAAH3cIAAAAEAAAAQ=="; // 恶意序列化数据
        userSessions.put("malicious_session", maliciousSession);
        
        // 模拟处理欢迎页面请求
        System.out.println("\
[Normal Session] ");
        handleWelcomeRequest("session_12345");
        
        System.out.println("\
[Attack Session] ");
        handleWelcomeRequest("malicious_session");
    }
}