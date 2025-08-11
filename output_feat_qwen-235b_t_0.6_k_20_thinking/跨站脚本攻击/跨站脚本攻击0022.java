import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class IoTDeviceServer {
    static List<Map<String, String>> devices = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/register", new PostHandler(data -> {
            String deviceName = data.get("name");
            String status = data.get("status");
            devices.add(Map.of("name", deviceName, "status", status));
            return "Device registered successfully";
        }));
        
        server.createContext("/dashboard", new GetHandler(() -> {
            StringBuilder html = new StringBuilder("<html><body><h1>IoT Devices</h1><ul>\
");
            devices.forEach(device -> html.append("<li>").append(device.get("name")).append(" - ").append(device.get("status")).append("</li>\
"));
            return html.append("</ul></body></html>").toString();
        }));
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class PostHandler implements HttpHandler {
        Function<Map<String, String>, String> handler;

        PostHandler(Function<Map<String, String>, String> handler) {
            this.handler = handler;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStreamReader reader = new InputStreamReader(exchange.getRequestBody());
                char[] buffer = new char[1024];
                int len = reader.read(buffer);
                String body = new String(buffer, 0, len);
                
                Map<String, String> data = new HashMap<>();
                for (String pair : body.split("&")) {
                    String[] kv = pair.split("=");
                    data.put(kv[0], kv[1]);
                }
                
                String response = handler.apply(data);
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }

    static class GetHandler implements HttpHandler {
        Function<Void, String> handler;

        GetHandler(Function<Void, String> handler) {
            this.handler = handler;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = handler.apply(null);
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}