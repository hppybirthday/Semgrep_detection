import java.io.*;
import java.net.*;
import java.nio.charset.*;
import java.util.*;
import java.util.function.*;
import java.util.logging.*;
import com.sun.net.httpserver.*;

class DataCleaner {
    private static final Logger logger = Logger.getLogger(DataCleaner.class.getName());

    static String fetchExternalData(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("Failed : HTTP Error code : "
                    + conn.getResponseCode());
        }

        BufferedReader br = new BufferedReader(
            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            response.append(line);
        }
        conn.disconnect();
        return response.toString();
    }

    static void startServer(int port) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/clean", exchange -> {
            try {
                Map<String, Object> response = new HashMap<>();
                String query = exchange.getRequestURI().getQuery();
                
                if (query == null || !query.startsWith("service=")) {
                    response.put("error", "Missing service parameter");
                    sendResponse(exchange, 400, response);
                    return;
                }

                String serviceUrl = query.substring(8);
                logger.info("Fetching data from: " + serviceUrl);
                
                // Vulnerable point: Direct use of user input in URL
                String rawData = fetchExternalData(serviceUrl);
                String cleanedData = rawData.replaceAll("[^a-zA-Z0-9]", " ");
                
                response.put("original", rawData);
                response.put("cleaned", cleanedData);
                sendResponse(exchange, 200, response);
                
            } catch (Exception e) {
                logger.severe("Error processing request: " + e.getMessage());
                Map<String, Object> error = new HashMap<>();
                error.put("error", e.getMessage());
                sendResponse(exchange, 500, error);
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    static void sendResponse(HttpExchange exchange, int code, Map<String, Object> response) throws IOException {
        String jsonResponse = response.toString();
        logger.info("Response: " + jsonResponse); // Log response content
        exchange.sendResponseHeaders(code, jsonResponse.length());
        OutputStream os = exchange.getResponseBody();
        os.write(jsonResponse.getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    public static void main(String[] args) throws Exception {
        startServer(8080);
    }
}