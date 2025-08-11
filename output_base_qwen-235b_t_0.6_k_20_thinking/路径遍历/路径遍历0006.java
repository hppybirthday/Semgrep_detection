package com.example.iot;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class VulnerableDeviceServer {
    private static final String BASE_DIR = "/var/data/sensor_logs/";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/download", new FileDownloadHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class FileDownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> params = queryToMap(exchange.getRequestURI().getQuery());
                String filename = (String) params.get("file");
                
                if (filename == null || filename.isEmpty()) {
                    sendResponse(exchange, 400, "Missing file parameter");
                    return;
                }

                try {
                    // Vulnerable path concatenation
                    Path filePath = new File(BASE_DIR + filename).toPath();
                    
                    // Security check bypass example
                    if (!filePath.normalize().startsWith(BASE_DIR)) {
                        sendResponse(exchange, 403, "Access denied");
                        return;
                    }

                    if (Files.exists(filePath)) {
                        String mimeType = Files.probeContentType(filePath);
                        exchange.getResponseHeaders().set("Content-Type", mimeType);
                        sendFile(exchange, filePath);
                    } else {
                        sendResponse(exchange, 404, "File not found");
                    }
                } catch (Exception e) {
                    sendResponse(exchange, 500, "Internal server error");
                    e.printStackTrace();
                }
            } else {
                sendResponse(exchange, 405, "Method not allowed");
            }
        }

        private void sendFile(HttpExchange exchange, Path filePath) throws IOException {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream os = exchange.getResponseBody();
                 InputStream is = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
        }

        private void sendResponse(HttpExchange exchange, int code, String message) throws IOException {
            exchange.sendResponseHeaders(code, message.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(message.getBytes());
            }
        }

        private Map<String, Object> queryToMap(String query) {
            Map<String, Object> result = new HashMap<>();
            if (query != null) {
                for (String param : query.split("&")) {
                    String[] entry = param.split("=");
                    if (entry.length > 1) {
                        result.put(entry[0], entry[1]);
                    } else {
                        result.put(entry[0], null);
                    }
                }
            }
            return result;
        }
    }
}