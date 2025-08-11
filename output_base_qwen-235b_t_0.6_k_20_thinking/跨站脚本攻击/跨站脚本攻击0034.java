import java.io.*;
import java.net.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class ChatServer {
    static List<String> messages = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/chat", new ChatHandler());
        server.createContext("/send", new SendHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class ChatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "<html><body><h1>Chat Room</h1><div style='height:300px;overflow:auto'>"
                + messages.stream().map(m -> "<div>" + m + "</div>").reduce((a, b) -> a + b).orElse("")
                + "</div><form action='/send' method='POST'>"
                + "<input type='text' name='msg' placeholder='Type message...'>"
                + "<input type='submit' value='Send'></form></body></html>";

            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class SendHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                String query = br.readLine();
                if (query != null && query.startsWith("msg=")) {
                    String message = query.substring(4);
                    messages.add(message);
                }
            }
            exchange.sendResponseHeaders(302, 0);
            exchange.getResponseHeaders().set("Location", "/chat");
            exchange.getResponseBody().close();
        }
    }
}