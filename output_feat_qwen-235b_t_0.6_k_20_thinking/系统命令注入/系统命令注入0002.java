import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import com.sun.net.httpserver.*;

public class ChatApp {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/fileinfo", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    // 读取请求体
                    InputStream is = exchange.getRequestBody();
                    String json = new BufferedReader(new InputStreamReader(is))
                        .lines().collect(java.util.stream.Collectors.joining("\
"));
                    
                    // 解析JSON（简单实现）
                    String filepath = json.split("filepath":")[1].split(",|")[0]
                        .replaceAll("[^a-zA-Z0-9_\\-./]", "");
                    
                    // 存在漏洞的命令执行
                    ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", 
                        String.format("ls -l %s | grep -v total", filepath));
                    Process process = pb.start();
                    
                    // 读取输出结果
                    String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                        .lines().collect(java.util.stream.Collectors.joining("\
"));
                    
                    // 发送响应
                    exchange.sendResponseHeaders(200, output.getBytes().length);
                    exchange.getResponseBody().write(output.getBytes());
                    
                } catch (Exception e) {
                    String error = "Error: " + e.getMessage();
                    exchange.sendResponseHeaders(500, error.length());
                    exchange.getResponseBody().write(error.getBytes());
                }
                exchange.getResponseBody().close();
            }
        });
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        server.setExecutor(executor);
        server.start();
        System.out.println("Server running on port 8000");
    }
}