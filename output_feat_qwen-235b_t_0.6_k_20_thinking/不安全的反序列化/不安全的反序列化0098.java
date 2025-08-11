import com.alibaba.fastjson.JSON;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

class ChatMessage implements java.io.Serializable {
    public String user;
    public String content;
}

public class ChatServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/send", new ChatHandler());
        server.start();
        System.out.println("Server started on port 8080");
    }

    static class ChatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream is = exchange.getRequestBody();
                String json = readStream(is);
                
                // Vulnerable deserialization
                ChatMessage msg = JSON.parseObject(json, ChatMessage.class);
                
                // Simulate message processing
                System.out.println("Received message from " + msg.user);
                System.out.println("Content: " + msg.content);
                
                String response = "Message received";
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
        
        private String readStream(InputStream is) throws IOException {
            StringBuilder sb = new StringBuilder();
            int b;
            while ((b = is.read()) != -1) {
                sb.append((char) b);
            }
            return sb.toString();
        }
    }
}