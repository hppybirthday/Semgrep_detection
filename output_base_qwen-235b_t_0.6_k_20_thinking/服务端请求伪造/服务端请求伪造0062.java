import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.util.function.*;

public class SSRFServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", new HttpHandler() {
            public void handle(HttpExchange exchange) {
                if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                    try {
                        BufferedReader reader = new BufferedReader(
                            new InputStreamReader(exchange.getRequestBody()));
                        String inputLine;
                        StringBuilder content = new StringBuilder();
                        while ((inputLine = reader.readLine()) != null) {
                            content.append(inputLine);
                        }
                        String urlParam = content.toString().split("=")[1];
                        
                        // Vulnerable code: Unvalidated URL input
                        URL targetUrl = new URL(URLDecoder.decode(urlParam, "UTF-8"));
                        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
                        connection.setRequestMethod("GET");
                        
                        BufferedReader in = new BufferedReader(
                            new InputStreamReader(connection.getInputStream()));
                        String outputLine;
                        StringBuilder response = new StringBuilder();
                        while ((outputLine = in.readLine()) != null) {
                            response.append(outputLine);
                        }
                        in.close();
                        
                        String responseStr = "Response: " + response.toString();
                        exchange.sendResponseHeaders(200, responseStr.getBytes().length);
                        OutputStream os = exchange.getResponseBody();
                        os.write(responseStr.getBytes());
                        os.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                        String error = "Error: " + e.getMessage();
                        try {
                            exchange.sendResponseHeaders(500, error.getBytes().length);
                            OutputStream os = exchange.getResponseBody();
                            os.write(error.getBytes());
                            os.close();
                        } catch (IOException ioException) {
                            ioException.printStackTrace();
                        }
                    }
                }
            }
        });
        
        // Simulated internal endpoint (mobile backend service)
        server.createContext("/secret", exchange -> {
            if (exchange.getRequestMethod().equals("GET")) {
                String secretData = "INTERNAL_SECRET_DATA_12345";
                exchange.sendResponseHeaders(200, secretData.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(secretData.getBytes());
                os.close();
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}