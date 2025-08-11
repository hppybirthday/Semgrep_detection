import java.io.*;
import java.net.*;
import java.nio.file.*;

class ChatServer {
    static final String BASE_DIR = "/var/chat_uploads/";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/chat", ChatServer::handleRequest);
        server.start();
    }

    static void handleRequest(HttpExchange exchange) {
        try {
            String query = exchange.getRequestURI().getQuery();
            String fileName = query.split("=")[1];
            
            // Vulnerable path construction
            File file = new File(BASE_DIR + fileName);
            
            if (!Files.exists(file.toPath())) {
                respond(exchange, "File not found", 404);
                return;
            }

            if (fileName.contains("..") || fileName.startsWith("/")) {
                respond(exchange, "Invalid path", 403);
                return;
            }

            Files.delete(file.toPath());
            respond(exchange, "Deleted: " + fileName, 200);
            
        } catch (Exception e) {
            respond(exchange, "Server error", 500);
        }
    }

    static void respond(HttpExchange exchange, String response, int code) {
        try {
            exchange.sendResponseHeaders(code, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        } catch (IOException e) {}
    }
}

/*
Example attack:
GET /chat?file=../../etc/passwd

Weaknesses:
1. Path validation happens after file construction
2. Primitive check for ../ can be bypassed with URL encoding (%2e%2e)
3. File deletion without proper access control
4. Static base path allows directory traversal when combined with relative paths
*/