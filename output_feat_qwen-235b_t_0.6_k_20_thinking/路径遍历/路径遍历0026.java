import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class DataCleaner {
    private static final String BASE_DIR = "/var/data/cleaner/";
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/process", new FileHandler());
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class FileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                Map<String, Object> response = new HashMap<>();
                int statusCode = 200;

                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                
                if (!params.containsKey("file")) {
                    response.put("error", "Missing file parameter");
                    statusCode = 400;
                } else {
                    String filename = params.get("file");
                    Path targetPath = Paths.get(BASE_DIR, filename);
                    
                    // Vulnerable path construction
                    if (!isSubPath(BASE_DIR, targetPath.toString())) {
                        response.put("error", "Invalid file path");
                        statusCode = 403;
                    } else {
                        byte[] fileContent = Files.readAllBytes(targetPath);
                        String cleanedContent = cleanData(fileContent);
                        
                        // Log cleaned data to vulnerable path
                        String logFilename = "clean_log_" + new Random().nextInt(1000) + ".log";
                        Path logPath = Paths.get(BASE_DIR, "logs/", logFilename);
                        Files.write(logPath, cleanedContent.getBytes());
                        
                        response.put("log_file", logPath.toString());
                        response.put("content_length", cleanedContent.length());
                    }
                }

                String jsonResponse = new Gson().toJson(response);
                exchange.sendResponseHeaders(statusCode, jsonResponse.length());
                OutputStream os = exchange.getResponseBody();
                os.write(jsonResponse.getBytes());
                os.close();
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, 0);
                exchange.getResponseBody().close();
                e.printStackTrace();
            }
        }

        private boolean isSubPath(String baseDir, String targetPath) {
            try {
                Path base = Paths.get(baseDir).toRealPath();
                Path target = Paths.get(targetPath).toRealPath();
                return target.startsWith(base);
            } catch (IOException e) {
                return false;
            }
        }

        private String cleanData(byte[] data) {
            // Simulated data cleaning process
            return new String(data).replaceAll("\\s+", " ").trim();
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> params = new HashMap<>();
            if (query != null) {
                for (String pair : query.split("&")) {
                    String[] keyValue = pair.split("=");
                    if (keyValue.length == 2) {
                        params.put(keyValue[0], keyValue[1]);
                    }
                }
            }
            return params;
        }
    }
}