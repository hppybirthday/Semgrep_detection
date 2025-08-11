package com.example.taskmanager;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import com.sun.net.httpserver.*;

public class TaskAttachmentServer {
    private static final String BASE_DIR = "/var/task_attachments/";
    private static final Pattern SAFE_PATH = Pattern.compile("^[a-zA-Z0-9_\\-\\.]+$");

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/download", new DownloadHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class DownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> params = queryToMap(exchange.getRequestURI().getQuery());
                String filename = (String) params.get("file");
                
                // 漏洞点：直接拼接用户输入
                Path filePath = Paths.get(BASE_DIR + filename);
                
                // 错误的路径校验（可被绕过）
                if (!isValidPath(filename)) {
                    sendError(exchange, 400, "Invalid file name");
                    return;
                }

                try {
                    byte[] fileBytes = Files.readAllBytes(filePath);
                    exchange.sendResponseHeaders(200, fileBytes.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(fileBytes);
                    os.close();
                } catch (Exception e) {
                    sendError(exchange, 500, "File not found");
                }
            } else {
                sendError(exchange, 405, "Method not allowed");
            }
        }

        private boolean isValidPath(String path) {
            // 正则校验存在绕过可能（例如编码绕过）
            return SAFE_PATH.matcher(path).matches();
        }

        private void sendError(HttpExchange exchange, int code, String message) throws IOException {
            exchange.sendResponseHeaders(code, message.length());
            OutputStream os = exchange.getResponseBody();
            os.write(message.getBytes());
            os.close();
        }

        private Map<String, Object> queryToMap(String query) {
            Map<String, Object> result = new HashMap<>();
            if (query != null) {
                Arrays.stream(query.split("&"))
                    .map(pair -> pair.split("="))
                    .forEach(pair -> result.put(pair[0], pair.length > 1 ? pair[1] : ""));
            }
            return result;
        }
    }
}