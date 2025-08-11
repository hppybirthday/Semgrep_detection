import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

public class ChatAppFileServer {
    private static final String BASE_DIR = "./user_files/";
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/download", exchange -> {
            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.sendResponseHeaders(405, 0);
                return;
            }

            URI requestURI = exchange.getRequestURI();
            String query = requestURI.getQuery();
            Map<String, String> params = queryToMap(query);

            String filename = params.get("file");
            if (filename == null || filename.isEmpty()) {
                exchange.sendResponseHeaders(400, 0);
                return;
            }

            // 错误的路径检查逻辑
            if (filename.contains("../") || filename.contains("..\\\\")) {
                exchange.sendResponseHeaders(403, 0);
                return;
            }

            Path filePath = Paths.get(BASE_DIR + filename);
            if (!Files.exists(filePath)) {
                exchange.sendResponseHeaders(404, 0);
                return;
            }

            exchange.sendResponseHeaders(200, 0);
            try (OutputStream os = exchange.getResponseBody();
                 InputStream is = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port " + PORT);
    }

    private static Map<String, String> queryToMap(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null) return result;
        for (String pair : query.split("&")) {
            String[] entry = pair.split("=");
            if (entry.length > 1) {
                result.put(entry[0], entry[1]);
            } else {
                result.put(entry[0], "");
            }
        }
        return result;
    }
}