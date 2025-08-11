import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

public class IoTDeviceController {
    private static final String BASE_DIR = "./device_logs/";

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/logs", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> params = parseQueryParams(exchange.getRequestURI().getQuery());
                String deviceId = (String) params.get("id");
                
                if (deviceId == null || deviceId.isEmpty()) {
                    sendResponse(exchange, 400, "Missing device ID");
                    return;
                }

                try {
                    String logContent = readDeviceLog(deviceId);
                    sendResponse(exchange, 200, logContent);
                } catch (Exception e) {
                    sendResponse(exchange, 500, "Error reading log: " + e.getMessage());
                }
            } else {
                sendResponse(exchange, 405, "Method not allowed");
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server running on port 8080");
    }

    private static String readDeviceLog(String deviceId) throws IOException {
        // 漏洞点：直接拼接用户输入构造文件路径
        File logFile = new File(BASE_DIR + deviceId + ".log");
        
        if (!logFile.exists()) {
            throw new FileNotFoundException("Device log not found");
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    private static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        exchange.sendResponseHeaders(code, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    private static Map<String, Object> parseQueryParams(String query) {
        Map<String, Object> params = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    params.put(pair[0], pair[1]);
                }
            }
        }
        return params;
    }
}