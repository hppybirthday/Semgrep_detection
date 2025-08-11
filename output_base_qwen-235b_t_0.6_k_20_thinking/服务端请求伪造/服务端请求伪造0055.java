import java.io.*;
import java.lang.annotation.*;
import java.net.*;
import java.util.*;
import com.sun.net.httpserver.*;

@Retention(RetentionPolicy.RUNTIME)
@interface RequestHandler {
    String path();
}

abstract class GameHandler implements HttpHandler {
    public abstract void handle(HttpExchange exchange);
}

public class GameServer {
    private static final Map<String, GameHandler> routes = new HashMap<>();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api", new GameHandler() {
            public void handle(HttpExchange exchange) {
                try {
                    String path = exchange.getRequestURI().getPath();
                    GameHandler handler = routes.get(path);
                    if (handler != null) {
                        handler.handle(exchange);
                    } else {
                        exchange.sendResponseHeaders(404, 0);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Game server started on port 8080");
        
        // 自动注册处理器
        registerHandlers();
    }

    static void registerHandlers() throws Exception {
        Class<?>[] handlers = {ImageHandler.class};
        for (Class<?> cls : handlers) {
            if (cls.isAnnotationPresent(RequestHandler.class)) {
                RequestHandler ann = (RequestHandler) cls.getAnnotation(RequestHandler.class);
                routes.put(ann.path(), (GameHandler) cls.getDeclaredConstructor().newInstance());
            }
        }
    }

    @RequestHandler("/fetchImage")
    static class ImageHandler extends GameHandler {
        public void handle(HttpExchange exchange) {
            try {
                // 漏洞点：直接使用用户输入的url参数
                String query = exchange.getRequestURI().getQuery();
                String imageUrl = java.net.URLDecoder.decode(query.split("=")[1], "UTF-8");
                
                URL url = new URL(imageUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                
                // 返回响应
                InputStream is = conn.getInputStream();
                exchange.sendResponseHeaders(200, 0);
                OutputStream os = exchange.getResponseBody();
                byte[] buffer = new byte[1024];
                int len;
                while ((len = is.read(buffer)) > 0) {
                    os.write(buffer, 0, len);
                }
                os.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}