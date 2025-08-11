import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.sql.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class VulnerableUserService {
    static Connection conn;

    public static void main(String[] args) throws Exception {
        // 初始化内存数据库
        conn = DriverManager.getConnection("jdbc:h2:mem:testdb");
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE users(id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
        stmt.execute("INSERT INTO users VALUES(1, 'admin', 'secret123')");

        // 启动HTTP服务
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/login", new LoginHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // 模拟参数获取
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                String username = params.get("username");
                String password = params.get("password");

                // 漏洞触发点：直接拼接SQL语句
                String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql);

                // 响应逻辑
                if (rs.next()) {
                    sendResponse(exchange, 200, "Login successful for " + rs.getString("username"));
                } else {
                    sendResponse(exchange, 401, "Authentication failed");
                }
            } catch (Exception e) {
                sendResponse(exchange, 500, "Internal server error");
            }
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> result = new HashMap<>();
            if (query != null) {
                for (String pair : query.split("&")) {
                    String[] entry = pair.split("=");
                    result.put(entry[0], entry[1]);
                }
            }
            return result;
        }

        private void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
            exchange.sendResponseHeaders(code, response.getBytes().length);
            exchange.getResponseBody().write(response.getBytes());
            exchange.getResponseBody().close();
        }
    }
}