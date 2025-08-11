import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;

class ChatServer {
    static List<String> messages = new ArrayList<>();
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/chat", new HttpHandler() {
            public void handle(HttpExchange exchange) {
                try {
                    if ("POST".equals(exchange.getRequestMethod())) {
                        BufferedReader reader = new BufferedReader(
                            new InputStreamReader(exchange.getRequestBody()));
                        String message = reader.lines().collect(Collectors.joining("\
"));
                        messages.add(message);
                        exchange.sendResponseHeaders(200, 0);
                    } else {
                        exchange.getResponseHeaders().set("Content-Type", "text/html");
                        String response = "<html><body><h1>Chat Room</h1>" + 
                            messages.stream().map(m -> "<div>" + m + "</div>").collect(Collectors.joining()) +
                            "<form method=POST action=/chat><input type=text name=message>" +
                            "<input type=submit value=Send></form></body></html>";
                        exchange.sendResponseHeaders(200, response.getBytes().length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(response.getBytes());
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }
}

@FunctionalInterface
interface HttpHandler extends com.sun.net.httpserver.HttpHandler {}

// 模拟攻击请求
// curl -X POST http://localhost:8000/chat -d '<script>alert(document.cookie)</script>'