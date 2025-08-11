import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

class IoTDeviceServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api/v1/device", exchange -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
                String deviceId = params.get("id");
                String fileName = params.get("file");
                
                // 模拟IoT设备数据存储路径
                String basePath = "/opt/iotsystem/sensor_data/";
                String response = "";
                
                try {
                    // 路径遍历漏洞点：未校验文件名中的特殊字符
                    Path filePath = Paths.get(basePath + deviceId + "/" + fileName);
                    
                    // 模拟设备认证
                    if (!isValidDevice(deviceId)) {
                        exchange.sendResponseHeaders(403, 0);
                        return;
                    }
                    
                    // 读取传感器数据文件
                    if (Files.exists(filePath)) {
                        response = new String(Files.readAllBytes(filePath));
                        exchange.sendResponseHeaders(200, response.length());
                    } else {
                        response = "File not found";
                        exchange.sendResponseHeaders(404, response.length());
                    }
                } catch (Exception e) {
                    response = "Error: " + e.getMessage();
                    exchange.sendResponseHeaders(500, response.length());
                }
                
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("IoT Server started on port 8080");
    }
    
    // 简单的设备ID验证（存在绕过可能）
    private static boolean isValidDevice(String deviceId) {
        return deviceId != null && deviceId.matches("device-\\d+");
    }
    
    // 查询参数解析
    private static Map<String, String> queryToMap(String query) {
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