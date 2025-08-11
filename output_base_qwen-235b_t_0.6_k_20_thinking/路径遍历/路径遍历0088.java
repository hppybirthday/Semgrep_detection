import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;

public class MLModelServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/model", new ModelHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class ModelHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String query = exchange.getRequestURI().getQuery();
                String modelName = "default";
                if (query != null && query.startsWith("model=")) {
                    modelName = query.substring(6);
                }

                String basePath = "/var/ml_models/";
                String filePath = basePath + modelName + ".model";
                
                // Simulate model loading
                byte[] modelData = Files.readAllBytes(Paths.get(filePath));
                
                exchange.sendResponseHeaders(200, modelData.length);
                OutputStream os = exchange.getResponseBody();
                os.write(modelData);
                os.close();
            } catch (Exception e) {
                String response = "Error: " + e.getMessage();
                exchange.sendResponseHeaders(500, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.getResponseBody().close();
            }
        }
    }
}