import java.io.*;
import java.net.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;
import com.fasterxml.jackson.databind.*;

@FunctionalInterface
interface HttpHandler extends Function<String, String> {}

public class SSRFDemo {
    static final ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api/data", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                processRequest(exchange);
            }
            exchange.close();
        });
        server.setExecutor(null);
        server.start();
    }

    static void processRequest(HttpExchange exchange) throws Exception {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(exchange.getRequestBody()));
        JsonNode payload = mapper.readTree(reader);

        List<String> bValues = parseArray(payload.get("b"));
        List<String> pValues = parseArray(payload.get("p"));
        
        // 漏洞点：直接使用用户输入构造URL
        String targetUrl = String.format("http://%s:%s/internal/%s",
            bValues.get(2), pValues.get(2), "ace-admin");

        HttpHandler handler = createHttpHandler();
        String response = handler.apply(targetUrl);

        exchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    static List<String> parseArray(JsonNode node) {
        return StreamSupport.stream(node.spliterator(), false)
            .map(JsonNode::asText)
            .collect(Collectors.toList());
    }

    static HttpHandler createHttpHandler() {
        return url -> {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("GET");
                
                if (conn.getResponseCode() == 200) {
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()));
                    return reader.lines().collect(Collectors.joining("\
"));
                }
                return "Error: " + conn.getResponseCode();
            } catch (Exception e) {
                return "Exception: " + e.getMessage();
            }
        };
    }
}