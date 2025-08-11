import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

public class FileServer {
    private static final String BASE_DIR = "/var/www/html";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/download", new DownloadHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    static class DownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = queryToMap(query);
                
                // 漏洞点：不安全的路径拼接
                String filename = params.get("file");
                if (filename == null || filename.isEmpty()) {
                    sendError(exchange, 400, "Missing file parameter");
                    return;
                }

                // 错误的防御措施
                filename = filename.replace("../", ""); // 单次替换不彻底
                
                Path filePath = Paths.get(BASE_DIR, filename);

                // 安全检查不充分
                if (!filePath.normalize().startsWith(BASE_DIR)) {
                    sendError(exchange, 403, "Forbidden");
                    return;
                }

                if (!Files.exists(filePath) || Files.isDirectory(filePath)) {
                    sendError(exchange, 404, "File not found");
                    return;
                }

                byte[] fileBytes = Files.readAllBytes(filePath);
                exchange.sendResponseHeaders(200, fileBytes.length);
                OutputStream os = exchange.getResponseBody();
                os.write(fileBytes);
                os.close();
            } catch (Exception e) {
                sendError(exchange, 500, "Internal server error");
                e.printStackTrace();
            }
        }

        private Map<String, String> queryToMap(String query) {
            Map<String, String> result = new HashMap<>();
            if (query == null) return result;
            
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                if (entry.length > 1) {
                    result.put(entry[0], entry[1]);
                }
            }
            return result;
        }

        private void sendError(HttpExchange exchange, int code, String message) throws IOException {
            exchange.sendResponseHeaders(code, message.length());
            OutputStream os = exchange.getResponseBody();
            os.write(message.getBytes());
            os.close();
        }
    }
}