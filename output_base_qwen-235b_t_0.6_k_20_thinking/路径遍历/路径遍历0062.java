import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class FileServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/files", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) {
                try {
                    String query = exchange.getRequestURI().getQuery();
                    String filename = query != null && query.startsWith("filename=") 
                        ? query.substring(9) : "default.txt";

                    Path filePath = Paths.get("./user_uploads/" + filename).normalize();
                    
                    // Vulnerable path concatenation without sanitization
                    if (!filePath.startsWith(Paths.get("./user_uploads/"))) {
                        sendError(exchange, 403, "Forbidden");
                        return;
                    }

                    if (Files.exists(filePath)) {
                        byte[] fileBytes = Files.readAllBytes(filePath);
                        exchange.sendResponseHeaders(200, fileBytes.length);
                        exchange.getResponseBody().write(fileBytes);
                    } else {
                        sendError(exchange, 404, "File Not Found");
                    }
                } catch (Exception e) {
                    sendError(exchange, 500, "Internal Server Error");
                } finally {
                    exchange.close();
                }
            }

            private void sendError(HttpExchange exchange, int code, String message) {
                try {
                    byte[] response = message.getBytes();
                    exchange.sendResponseHeaders(code, response.length);
                    exchange.getResponseBody().write(response);
                } catch (IOException e) {
                    // Silent fail
                }
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("Server running on port 8000");
    }
}