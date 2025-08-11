import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;

class DeviceFileManager {
    private static final String BASE_DIR = "/opt/iot_device_data/";
    
    // 模拟设备固件更新接口（存在路径遍历漏洞）
    public static void handleFirmwareUpdate(String pluginId, String content) throws IOException {
        // 危险操作：直接拼接用户输入到文件路径
        String filePath = BASE_DIR + "plugins/" + pluginId + "/firmware.bin";
        File targetFile = new File(filePath);
        
        // 创建父目录（如果不存在）
        targetFile.getParentFile().mkdirs();
        
        // 写入用户提供的内容
        FileUtils.writeLines(targetFile, Arrays.asList(content.split("\\\\|")));
        System.out.println("[+] Firmware updated: " + filePath);
    }
    
    // 模拟日志清理功能（使用危险的文件删除操作）
    public static void clearDeviceLogs(String logPath) throws IOException {
        File logFile = new File(BASE_DIR + "logs/" + logPath);
        if (logFile.exists()) {
            FileUtils.deleteQuietly(logFile);
            System.out.println("[+] Log file cleared: " + logFile.getAbsolutePath());
        }
    }
}

public class IoTDeviceServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/update_firmware", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("POST".equals(exchange.getRequestMethod())) {
                    try {
                        // 从请求体获取参数（模拟不安全的输入处理）
                        InputStream requestBody = exchange.getRequestBody();
                        String body = IOUtils.toString(requestBody, "UTF-8");
                        Map<String, String> params = parseParams(body);
                        
                        // 危险调用：将用户输入直接传递给文件操作
                        DeviceFileManager.handleFirmwareUpdate(
                            params.get("plugin_id"),
                            params.get("data")
                        );
                        
                        String response = "Firmware update successful";
                        exchange.sendResponseHeaders(200, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                    } catch (Exception e) {
                        String response = "Error: " + e.getMessage();
                        exchange.sendResponseHeaders(500, response.length());
                        exchange.getResponseBody().write(response.getBytes());
                    }
                }
            }
        });
        
        server.createContext("/clear_logs", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> queryParams = parseQuery(exchange.getRequestURI().getQuery());
                    try {
                        // 未验证路径参数
                        DeviceFileManager.clearDeviceLogs(queryParams.get("path"));
                        exchange.sendResponseHeaders(200, 0);
                    } catch (Exception e) {
                        exchange.sendResponseHeaders(500, 0);
                    }
                }
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("[*] IoT Device Server started on port 8080");
    }
    
    // 简单的参数解析方法（存在安全缺陷）
    private static Map<String, String> parseParams(String body) {
        Map<String, String> params = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                params.put(kv[0], kv[1]);
            }
        }
        return params;
    }
    
    private static Map<String, String> parseQuery(String query) {
        return parseParams(query);
    }
}