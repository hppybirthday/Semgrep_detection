import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class IoTDeviceServer {
    private static final String API_KEY = "iot_admin_secret_123";

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new java.net.InetSocketAddress(8000), 0);
        server.createContext("/api/device/data", new DataFetchHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class DataFetchHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) {
            try {
                String query = exchange.getRequestURI().getQuery();
                String sensorUrl = query != null && query.contains("url=") 
                    ? query.split("url=")[1].split("&")[0] 
                    : "http://default-sensor.local/status";

                Function<String, String> fetchData = url -> {
                    try {
                        URL targetUrl = new URL(url);
                        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
                        conn.setRequestProperty("Authorization", "Bearer " + API_KEY);
                        conn.setConnectTimeout(2000);
                        conn.setReadTimeout(2000);
                        
                        if (conn.getResponseCode() == 200) {
                            return new String(conn.getInputStream().readAllBytes());
                        }
                        return "Error: " + conn.getResponseCode();
                    } catch (Exception e) {
                        return "Fetch error: " + e.getMessage();
                    }
                };

                CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> fetchData.apply(sensorUrl));
                future.thenAccept(response -> {
                    try {
                        exchange.sendResponseHeaders(200, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }).join();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}