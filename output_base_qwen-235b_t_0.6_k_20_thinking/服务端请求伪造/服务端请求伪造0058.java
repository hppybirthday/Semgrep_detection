import java.io.*;
import java.net.*;
import java.util.*;
import java.nio.file.*;
import com.sun.net.httpserver.*;

class DataCleaner {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/clean", (exchange) -> {
            try {
                String query = exchange.getRequestURI().getQuery();
                String[] params = query.split("&");
                String csvUrl = "";
                
                for (String param : params) {
                    if (param.startsWith("url=")) {
                        csvUrl = param.substring(4);
                    }
                }
                
                if (csvUrl.isEmpty()) {
                    exchange.sendResponseHeaders(400, 0);
                    return;
                }
                
                // Vulnerable code: Directly using user input to create HTTP request
                URL url = new URL(csvUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
                StringBuilder cleanedData = new StringBuilder();
                
                String line;
                while ((line = reader.readLine()) != null) {
                    // Simple CSV cleaning: remove empty lines and trim spaces
                    if (!line.trim().isEmpty()) {
                        cleanedData.append(line.trim()).append("\
");
                    }
                }
                
                exchange.sendResponseHeaders(200, cleanedData.length());
                OutputStream os = exchange.getResponseBody();
                os.write(cleanedData.toString().getBytes());
                os.close();
                
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, 0);
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}