import java.net.*;
import java.io.*;
import com.sun.net.httpserver.*;

public class CRMSSRF {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/fetch", exchange -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                String uri = exchange.getRequestURI().toString();
                String[] parts = uri.split("=", 2);
                if (parts.length < 2) {
                    sendResponse(exchange, "Missing URL parameter", 400);
                    return;
                }
                String targetUrl = parts[1];
                
                try {
                    URL url = new URL(targetUrl);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    sendResponse(exchange, response.toString(), 200);
                } catch (Exception e) {
                    sendResponse(exchange, "Error fetching resource: " + e.getMessage(), 500);
                }
            } else {
                sendResponse(exchange, "Method not allowed", 405);
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }
    
    private static void sendResponse(HttpExchange exchange, String response, int code) throws IOException {
        exchange.sendResponseHeaders(code, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}