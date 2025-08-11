import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.function.*;
import com.sun.net.httpserver.*;

public class CRMFileServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/download", exchange -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                String query = exchange.getRequestURI().getQuery();
                String fileName = "default.txt";
                
                if (query != null && query.startsWith("file=")) {
                    fileName = query.substring(5);
                }
                
                // 路径遍历漏洞点：未校验用户输入
                Path basePath = Paths.get("/var/crm/files");
                Path targetPath = basePath.resolve(fileName).normalize();
                
                if (!targetPath.startsWith(basePath)) {
                    sendError(exchange, 403, "Forbidden");
                    return;
                }
                
                if (!Files.exists(targetPath)) {
                    sendError(exchange, 404, "Not Found");
                    return;
                }
                
                // 函数式风格读取文件内容
                String content = new String(Files.readAllBytes(targetPath));
                String response = String.format("<pre>%s</pre>", content);
                
                exchange.sendResponseHeaders(200, response.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            }
        });
        
        server.createContext("/", exchange -> {
            String html = "<html><body><h3>CRM文件下载中心</h3>"
                + "<form action=\\"/download\\" method=\\"get\\">"
                + "文件名：<input type=\\"text\\" name=\\"file\\" value=\\"notes.txt\\">"
                + "<input type=\\"submit\\" value=\\"下载\\"></form></body></html>";
            exchange.sendResponseHeaders(200, html.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(html.getBytes());
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }
    
    private static void sendError(HttpExchange exchange, int code, String message) throws IOException {
        String response = String.format("<h1>%d %s</h1>", code, message);
        exchange.sendResponseHeaders(code, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }
}