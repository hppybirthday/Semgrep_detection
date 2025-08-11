import java.io.*;
import java.net.*;
import com.sun.net.httpserver.*;

class IoTServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/device/data", new DataHandler());
        server.setExecutor(null);
        server.start();
    }
}

class DataHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String targetUrl = "http://default-device.local/status";
        
        if (query != null && query.contains("url=")) {
            targetUrl = query.split("url=")[1].split("&")[0];
        }

        try {
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            
            exchange.sendResponseHeaders(200, content.length());
            OutputStream os = exchange.getResponseBody();
            os.write(content.toString().getBytes());
            os.close();
            
        } catch (Exception e) {
            String error = "Error fetching device data: " + e.getMessage();
            exchange.sendResponseHeaders(500, error.length());
            OutputStream os = exchange.getResponseBody();
            os.write(error.getBytes());
            os.close();
        }
    }
}