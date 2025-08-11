import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

@FunctionalInterface
interface RequestHandler {
    void handle(HttpExchange exchange) throws IOException;
}

public class FileServer {
    private static final String BASE_DIR = "/data/data/com.example.app/files/";

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/download", createRequestHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    private static RequestHandler createRequestHandler() {
        return exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
                String filename = params.getOrDefault("file", "default.txt");
                
                // 路径遍历漏洞点：直接拼接用户输入
                Path filePath = Paths.get(BASE_DIR + filename);
                
                if (Files.exists(filePath)) {
                    sendFileContent(exchange, filePath);
                } else {
                    sendError(exchange, 404, "File not found");
                }
            } else {
                sendError(exchange, 405, "Method not allowed");
            }
        };
    }

    private static void sendFileContent(HttpExchange exchange, Path filePath) throws IOException {
        exchange.sendResponseHeaders(200, 0);
        try (InputStream in = Files.newInputStream(filePath);
             OutputStream out = exchange.getResponseBody()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = in.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
        }
    }

    private static void sendError(HttpExchange exchange, int code, String message) throws IOException {
        exchange.sendResponseHeaders(code, message.length());
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(message.getBytes());
        }
    }

    private static Map<String, String> parseQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null) {
            Arrays.stream(query.split("&"))
                .map(pair -> pair.split("="))
                .forEach(parts -> {
                    if (parts.length == 2) {
                        try {
                            params.put(URLDecoder.decode(parts[0], "UTF-8"),
                                      URLDecoder.decode(parts[1], "UTF-8"));
                        } catch (UnsupportedEncodingException e) {
                            // 忽略异常处理
                        }
                    }
                });
        }
        return params;
    }
}