import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.function.Function;
import java.util.stream.Collectors;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;

public class ChatApp {
    static class ChatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "";
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                String query = br.lines().collect(Collectors.joining("\
"));
                
                // Vulnerable function: Unrestricted URL access
                Function<String, String> fetchContent = url -> {
                    try {
                        URL target = new URL(url);
                        BufferedReader reader = new BufferedReader(
                            new InputStreamReader(target.openStream()));
                        return reader.lines().collect(Collectors.joining("\
"));
                    } catch (Exception e) {
                        return "Error: " + e.getMessage();
                    }
                };

                if (query.startsWith("image=")) {
                    String imageUrl = query.substring(6);
                    response = fetchContent.apply(imageUrl);
                } else {
                    response = "Invalid request";
                }
            }
            
            exchange.sendResponseHeaders(200, response.getBytes().length);
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/chat", new ChatHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Chat server started on port 8080");
    }
}