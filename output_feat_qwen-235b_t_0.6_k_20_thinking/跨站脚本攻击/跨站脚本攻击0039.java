import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class GameManager {
    static class CategoryService {
        Map<String, String> categories = new HashMap<>();
        
        void addCategory(String id, String parentId, String name) {
            // 漏洞点：直接存储未经验证的输入
            categories.put(id, String.format("{\\"id\\":\\"%s\\",\\"parentId\\":\\"%s\\",\\"name\\":\\"%s\\"}", 
                          id, parentId, name));
        }
        
        String getCategory(String id) {
            return categories.getOrDefault(id, "{}");
        }
    }
    
    static class XSSRequestHandler implements HttpHandler {
        CategoryService service = new CategoryService();
        
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            URI uri = exchange.getRequestURI();
            Map<String, String> params = queryToMap(uri.getQuery());
            
            if (uri.getPath().equals("/addCategory")) {
                String id = params.get("id");
                String parentId = params.get("parentId");
                String name = params.get("name");
                
                // 漏洞点：未对用户输入进行转义
                service.addCategory(id, parentId, name);
                String response = String.format("<script>parent.updateCategory(%s)</script>", 
                                          service.getCategory(id));
                sendResponse(exchange, response);
            } 
            else if (uri.getPath().equals("/viewCategory")) {
                String id = params.get("id");
                // 漏洞点：直接输出存储的恶意内容
                String response = String.format("<html><body>%s</body></html>", 
                                          service.getCategory(id));
                sendResponse(exchange, response);
            }
        }
        
        private Map<String, String> queryToMap(String query) {
            Map<String, String> result = new HashMap<>();
            if (query != null) {
                for (String param : query.split("&")) {
                    String[] entry = param.split("=");
                    result.put(entry[0], entry.length > 1 ? entry[1] : "");
                }
            }
            return result;
        }
        
        private void sendResponse(HttpExchange exchange, String response) throws IOException {
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/game", new XSSRequestHandler());
        server.start();
        System.out.println("Server started on port 8000");
    }
}