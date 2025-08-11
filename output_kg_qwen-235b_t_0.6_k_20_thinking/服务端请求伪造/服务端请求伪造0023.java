import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

// 桌面游戏服务器端类
public class GameServer {
    private ResourceLoader resourceLoader = new ResourceLoader();

    // 处理客户端请求的接口
    public String handleClientRequest(String resourceUrl) {
        try {
            // 直接使用客户端传来的URL参数
            return resourceLoader.loadResource(resourceUrl);
        } catch (Exception e) {
            return "Error loading resource: " + e.getMessage();
        }
    }

    // 模拟游戏客户端
    public static class GameClient {
        private GameServer server;

        public GameClient(GameServer server) {
            this.server = server;
        }

        // 客户端发送请求方法
        public String sendRequest(String resourceUrl) {
            System.out.println("[Client] Requesting: " + resourceUrl);
            return server.handleClientRequest(resourceUrl);
        }
    }

    // 资源加载器类（存在漏洞的关键点）
    private static class ResourceLoader {
        // 存在漏洞的资源加载方法
        public String loadResource(String resourceUrl) throws IOException {
            URL url = new URL(resourceUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            // 无任何安全校验直接访问目标资源
            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
            }
            return response.toString();
        }
    }

    // 模拟游戏服务器主程序
    public static void main(String[] args) {
        GameServer server = new GameServer();
        GameClient client = new GameClient(server);

        // 正常请求示例（安全场景）
        System.out.println("Normal request:");
        System.out.println(client.sendRequest("https://example.com/leaderboard.json"));
        
        // 恶意请求示例（SSRF攻击）
        System.out.println("\
Malicious SSRF attack:");
        System.out.println(client.sendRequest("file:///etc/passwd"));
        
        // 内网穿透示例
        System.out.println("\
Internal network attack:");
        System.out.println(client.sendRequest("http://127.0.0.1:8080/admin/config"));
    }
}