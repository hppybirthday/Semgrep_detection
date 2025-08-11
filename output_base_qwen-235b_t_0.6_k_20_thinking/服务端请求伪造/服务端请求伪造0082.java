import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

public class ChatServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/send", (HttpExchange exchange) -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                InputStreamReader reader = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                String body = new BufferedReader(reader).lines()
                    .collect(java.util.stream.Collectors.joining("\
"));

                String url = body.split("=")[1]; // 漏洞点：直接使用用户输入
                String response = fetchContent(url);

                byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, responseBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Chat server started on port 8080");
    }

    private static String fetchContent(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            return content.toString();
        } catch (Exception e) {
            return "Error fetching content: " + e.getMessage();
        }
    }
}