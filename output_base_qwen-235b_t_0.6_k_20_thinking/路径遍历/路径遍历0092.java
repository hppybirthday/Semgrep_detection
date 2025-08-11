import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

class CRMFileServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/download", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, List<String>> params = parseQuery(exchange.getRequestURI().getQuery());
                params.getOrDefault("filename", List.of()).stream().findFirst().ifPresent(filename -> {
                    try {
                        Path basePath = Paths.get("/var/crm/uploads");
                        Path targetPath = basePath.resolve(filename);
                        if (Files.exists(targetPath)) {
                            byte[] fileBytes = Files.readAllBytes(targetPath);
                            exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                            exchange.sendResponseHeaders(200, fileBytes.length);
                            exchange.getResponseBody().write(fileBytes);
                        } else {
                            sendError(exchange, "File not found");
                        }
                    } catch (Exception e) {
                        sendError(exchange, "Internal server error");
                    }
                });
            } else {
                sendError(exchange, "Method not allowed");
            }
            exchange.close();
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server running on port 8000");
    }

    private static void sendError(HttpExchange exchange, String message) {
        try {
            byte[] response = message.getBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(400, response.length);
            exchange.getResponseBody().write(response);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, List<String>> parseQuery(String query) {
        Map<String, List<String>> result = new HashMap<>();
        if (query != null) {
            Arrays.stream(query.split("&")).forEach(param -> {
                String[] pair = param.split("=");
                result.computeIfAbsent(pair[0], k -> new ArrayList<>()).add(pair.length > 1 ? pair[1] : "");
            });
        }
        return result;
    }
}