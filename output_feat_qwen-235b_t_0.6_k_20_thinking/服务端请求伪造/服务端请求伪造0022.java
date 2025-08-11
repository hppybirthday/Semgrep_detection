import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class IoTDataCollector {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/data", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                Map<String, String> params = parseQuery(exchange.getRequestURI());
                String targetUrl = params.get("url");
                
                if (targetUrl == null) {
                    sendResponse(exchange, 400, "Missing URL parameter");
                    return;
                }

                try {
                    HttpClient client = HttpClient.newHttpClient();
                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .build();
                    
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    sendResponse(exchange, 200, response.body());
                } catch (Exception e) {
                    sendResponse(exchange, 500, "Error fetching data: " + e.getMessage());
                }
            }
        });
        server.start();
        System.out.println("Server started on port 8000");
    }

    private static Map<String, String> parseQuery(URI uri) {
        if (uri.getQuery() == null) return new HashMap<>();
        return Arrays.stream(uri.getQuery().split("&"))
            .map(pair -> pair.split("=", 2))
            .filter(arr -> arr.length == 2)
            .collect(Collectors.toMap(
                arr -> arr[0], 
                arr -> arr[1],
                (existing, replacement) -> existing
            ));
    }

    private static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        byte[] bytes = response.getBytes();
        exchange.sendResponseHeaders(code, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }
}