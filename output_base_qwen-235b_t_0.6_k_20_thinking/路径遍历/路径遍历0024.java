import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;

public class MLModelServer {
    private static final String MODEL_DIR = "./models/";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/loadModel", new ModelHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class ModelHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
                String modelPath = params.get("path");
                
                // 模拟防御式编程错误：尝试过滤但存在绕过漏洞
                if (modelPath == null || modelPath.contains("..")) {
                    String response = "Invalid model path";
                    exchange.sendResponseHeaders(400, response.length());
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                    return;
                }

                Path fullPath = Paths.get(MODEL_DIR + modelPath).normalize();
                if (!fullPath.startsWith(MODEL_DIR)) {
                    String response = "Access denied";
                    exchange.sendResponseHeaders(403, response.length());
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                    return;
                }

                try {
                    byte[] modelData = Files.readAllBytes(fullPath);
                    exchange.sendResponseHeaders(200, modelData.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(modelData);
                    }
                } catch (IOException e) {
                    String response = "Model not found";
                    exchange.sendResponseHeaders(404, response.length());
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            }
        }

        private Map<String, String> queryToMap(String query) {
            Map<String, String> result = new HashMap<>();
            if (query != null) {
                for (String param : query.split("&")) {
                    String[] entry = param.split("=");
                    if (entry.length > 1) {
                        result.put(entry[0], entry[1]);
                    }
                }
            }
            return result;
        }
    }
}