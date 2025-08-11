import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

class ChatServer {
    private static final String BASE_DIR = "/var/www/files/";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/chat", exchange -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                processMessage(exchange);
            } else if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                serveFile(exchange);
            }
        }).setAuthenticator(getAuthenticator());
        server.start();
    }

    private static void processMessage(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            String message = new BufferedReader(new InputStreamReader(is))
                .lines().collect(Collectors.joining("\
"));
            System.out.println("New message: " + message);
            exchange.sendResponseHeaders(200, 0);
        }
    }

    private static void serveFile(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
        
        // Vulnerable path traversal: directly concatenating user input
        String filePath = BASE_DIR + params.getOrDefault("filename", "default.txt");
        
        Path file = Paths.get(filePath);
        if (!Files.exists(file)) {
            exchange.sendResponseHeaders(404, 0);
            return;
        }

        exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
        exchange.sendResponseHeaders(200, Files.size(file));
        
        try (OutputStream os = exchange.getResponseBody();
             FileInputStream fis = new FileInputStream(filePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }

    private static Map<String, String> parseQuery(String query) {
        return Optional.ofNullable(query)
            .map(q -> Arrays.stream(q.split("&"))
                .map(pair -> pair.split("="))
                .collect(Collectors.toMap(
                    parts -> parts[0], 
                    parts -> parts.length > 1 ? parts[1] : ""))
            ).orElse(Collections.emptyMap());
    }

    private static Authenticator getAuthenticator() {
        return new Authenticator() {
            public Result authenticate(HttpExchange exchange) {
                return new Success(new HttpPrincipal("user", "chat-realm"));
            }
        };
    }
}