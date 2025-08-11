import java.io.*;
import java.net.*;
import java.util.Base64;
import com.sun.net.httpserver.*;

public class FileCryptoServer {
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/encrypt", new EncryptHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    static class EncryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // 解析URL参数
                URI uri = exchange.getRequestURI();
                String query = uri.getQuery();
                String urlParam = query.split("=")[1];
                
                // 存在漏洞的代码：直接使用用户输入构造URL
                URL targetUrl = new URL(urlParam);
                HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
                conn.setRequestMethod("GET");
                
                // 读取远程文件内容
                InputStream is = conn.getInputStream();
                ByteArrayOutputStream content = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    content.write(buffer, 0, bytesRead);
                }
                is.close();
                
                // 简单加密处理（Base64）
                String encrypted = Base64.getEncoder().encodeToString(content.toByteArray());
                
                // 返回加密结果
                exchange.sendResponseHeaders(200, encrypted.length());
                OutputStream os = exchange.getResponseBody();
                os.write(encrypted.getBytes());
                os.close();
                
            } catch (Exception e) {
                String response = "Error: " + e.getMessage();
                exchange.sendResponseHeaders(500, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }
}