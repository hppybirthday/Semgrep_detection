import java.io.*;
import java.net.*;
import java.util.logging.*;
import com.sun.net.httpserver.*;

// 用户数据实体类
class UserProfile implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private String email;
    
    public UserProfile(String username, String email) {
        this.username = username;
        this.email = email;
    }
    
    public String getUsername() { return username; }
    public String getEmail() { return email; }
}

// 用户服务类
class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class.getName());
    
    public void saveUserProfile(UserProfile profile) {
        // 模拟数据库保存操作
        logger.info("Saving profile: " + profile.getUsername() + ", " + profile.getEmail());
        // 实际业务逻辑中可能会触发更多对象交互
        if(profile.getUsername().contains("admin")) {
            logger.warning("Admin profile detected - special handling");
        }
    }
}

// 漏洞存在的REST处理器
class UserHandler implements HttpHandler {
    private UserService userService = new UserService();
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            // 危险的反序列化操作
            ObjectInputStream ois = new ObjectInputStream(exchange.getRequestBody());
            Object obj = ois.readObject();
            
            if(obj instanceof UserProfile) {
                UserProfile profile = (UserProfile) obj;
                userService.saveUserProfile(profile);
                String response = "Profile saved successfully";
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } else {
                exchange.sendResponseHeaders(400, -1);
            }
        } catch (Exception e) {
            Logger.getLogger(UserHandler.class.getName()).log(Level.SEVERE, null, e);
            exchange.sendResponseHeaders(500, -1);
        }
    }
}

// 主程序入口
public class InsecureDeserializationApp {
    private static final Logger logger = Logger.getLogger(InsecureDeserializationApp.class.getName());
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/user/profile", new UserHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        logger.info("Server started on port 8000");
    }
}