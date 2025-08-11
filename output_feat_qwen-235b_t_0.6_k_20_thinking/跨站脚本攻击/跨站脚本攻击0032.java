import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;
import com.sun.net.httpserver.*;

public class FileCrypt {
    static final Map<String, String> sessions = new HashMap<>();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/upload", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String fileName = parseFileName(exchange);
                    String encrypted = encryptFile(fileName);
                    String response = String.format(
                        "<html><body><h2>加密成功！文件名: %s</h2>"
                        + "<script>document.write('会话ID:'+document.cookie)</script>"
                        + "</body></html>",
                        fileName
                    );
                    sendResponse(exchange, response);
                } catch (Exception e) {
                    sendError(exchange, "Invalid input: " + e.getMessage());
                }
            }
        });

        server.createContext("/decrypt", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String token = params.getOrDefault("token", "unknown");
                String decrypted = sessions.getOrDefault(token, "无数据");
                String response = String.format(
                    "<html><body><h2>解密结果: %s</h2>"
                    + "<button onclick=\\"location.href='/?search='+document.cookie\\">继续\\"</button>"
                    + "</body></html>",
                    decrypted
                );
                sendResponse(exchange, response);
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("服务启动在 http://localhost:8000/");
    }

    static String parseFileName(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        return reader.lines().collect(Collectors.joining("\
"));
    }

    static String encryptFile(String content) {
        String token = Base64.getEncoder().encodeToString(content.getBytes());
        sessions.put(token, content);
        return token;
    }

    static void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "text/html");
        exchange.sendResponseHeaders(200, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    static void sendError(HttpExchange exchange, String message) throws IOException {
        String response = String.format("<html><body><h3 style='color:red'>%s</h3></body></html>", message);
        exchange.sendResponseHeaders(400, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    static Map<String, String> parseQuery(String query) {
        return Arrays.stream(Optional.ofNullable(query).orElse("").split("&"))
            .map(pair -> pair.split("=", 2))
            .filter(arr -> arr.length == 2)
            .collect(Collectors.toMap(arr -> arr[0], arr -> arr[1]));
    }
}