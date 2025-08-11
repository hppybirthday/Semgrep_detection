import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import com.sun.net.httpserver.*;

public class DataCleaner {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/clean", (HttpExchange exchange) -> {
            try {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                String filename = params.get("file");
                
                // 路径遍历漏洞点：直接拼接用户输入
                Path filePath = Paths.get("./data/" + filename);
                
                if (!Files.exists(filePath)) {
                    String response = "File not found";
                    exchange.sendResponseHeaders(404, response.length());
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                    return;
                }

                // 读取文件并清洗（示例：转大写）
                List<String> cleaned = Files.readLines(filePath.toFile(), Charset.defaultCharset())
                    .stream()
                    .map(String::toUpperCase)
                    .toList();

                String response = String.join("\
", cleaned);
                exchange.sendResponseHeaders(200, response.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } catch (Exception e) {
                String response = "Server error: " + e.getMessage();
                exchange.sendResponseHeaders(500, response.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null) return result;
        
        Arrays.stream(query.split("&"))
            .map(pair -> pair.split("="))
            .forEach(parts -> {
                if (parts.length == 2) {
                    result.put(decode(parts[0]), decode(parts[1]));
                }
            });
        return result;
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}