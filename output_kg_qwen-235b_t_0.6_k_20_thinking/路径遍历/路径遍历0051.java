import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.function.*;
import java.util.stream.*;

public class VulnerableFileServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/download", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                String query = exchange.getRequestURI().getQuery();
                Function<String, String> getParam = key -> {
                    return java.util.Arrays.stream(query.split("&"))
                        .filter(s -> s.startsWith(key + "="))
                        .map(s -> s.replaceFirst(".*=", ""))
                        .findFirst().orElse("");
                };

                String filename = getParam.apply("file");
                // 路径遍历漏洞点：直接拼接用户输入
                String basePath = "/var/www/files/";
                Path filePath = Paths.get(basePath + filename);

                if (Files.exists(filePath)) {
                    exchange.sendResponseHeaders(200, 0);
                    try (OutputStream os = exchange.getResponseBody();
                         InputStream is = Files.newInputStream(filePath)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = is.read(buffer)) > 0) {
                            os.write(buffer, 0, len);
                        }
                    }
                } else {
                    String response = "File not found";
                    exchange.sendResponseHeaders(404, response.length());
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }
}