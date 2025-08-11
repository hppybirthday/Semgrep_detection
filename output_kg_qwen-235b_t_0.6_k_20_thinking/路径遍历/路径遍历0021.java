import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class IoTDeviceServer {
    private static final String BASE_DIR = "/var/iot/device_data/";
    
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/download", exchange -> {
            try {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String filename = params.getOrDefault("file", "default.log");
                
                // Vulnerable path construction
                Path filePath = Paths.get(BASE_DIR, filename);
                
                if (!filePath.normalize().startsWith(BASE_DIR)) {
                    sendResponse(exchange, 403, "Forbidden: Attempted path traversal");
                    return;
                }

                if (!Files.exists(filePath)) {
                    sendResponse(exchange, 404, "File not found");
                    return;
                }

                String content = readSecurely(filePath);
                sendResponse(exchange, 200, content);
                
            } catch (Exception e) {
                sendResponse(exchange, 500, "Internal server error");
                e.printStackTrace();
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("IoT Server started on port 8080");
    }

    private static String readSecurely(Path path) throws IOException {
        // Simulate secure reading
        return Files.readLines(path, Charset.defaultCharset()).stream()
            .map(line -> line.replaceAll("[a-zA-Z0-9]", "*"))
            .collect(Collectors.joining("\
"));
    }

    private static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        exchange.sendResponseHeaders(code, response.getBytes().length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    private static Map<String, String> parseQuery(String query) {
        return Optional.ofNullable(query)
            .map(q -> Arrays.stream(q.split("&"))
                .map(pair -> pair.split("="))
                .collect(Collectors.toMap(
                    parts -> parts[0],
                    parts -> parts.length > 1 ? parts[1] : "")))
            .orElse(Collections.emptyMap());
    }
}