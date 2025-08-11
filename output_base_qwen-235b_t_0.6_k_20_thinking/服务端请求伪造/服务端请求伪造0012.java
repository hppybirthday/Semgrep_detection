import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import java.util.function.*;
import com.fasterxml.jackson.databind.*;

public class CRMDataImporter {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Map<String, String> dbConfig = new HashMap<>();

    static {
        dbConfig.put("internal_db", "jdbc:mysql://localhost:3306/crm_data");
        dbConfig.put("backup_db", "jdbc:mysql://192.168.1.100:3306/backup");
    }

    public static void main(String[] args) throws Exception {
        startServer(8080);
    }

    private static void startServer(int port) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/import", exchange -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                String urlParam = exchange.getRequestURI().getQuery();
                
                if (urlParam == null || !urlParam.startsWith("url=")) {
                    sendResponse(exchange, 400, "Missing url parameter");
                    return;
                }

                String targetUrl = urlParam.substring(4);
                try {
                    String data = fetchData(targetUrl);
                    List<Customer> customers = parseCSV(data);
                    saveToDatabase(customers);
                    sendResponse(exchange, 200, "Imported " + customers.size() + " customers");
                } catch (Exception e) {
                    sendResponse(exchange, 500, "Import failed: " + e.getMessage());
                }
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port " + port);
    }

    private static String fetchData(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
        }

        BufferedReader br = new BufferedReader(new InputStreamReader((InputStream) conn.getContent()));
        return br.lines().collect(Collectors.joining("\
"));
    }

    private static List<Customer> parseCSV(String data) {
        return Arrays.stream(data.split("\
"))
            .skip(1)
            .map(line -> {
                String[] parts = line.split(",");
                return new Customer(parts[0], parts[1], parts[2]);
            })
            .collect(Collectors.toList());
    }

    private static void saveToDatabase(List<Customer> customers) {
        customers.forEach(c -> System.out.println("Saved: " + c));
    }

    private static void sendResponse(HttpExchange exchange, int code, String message) throws IOException {
        exchange.sendResponseHeaders(code, message.length());
        OutputStream os = exchange.getResponseBody();
        os.write(message.getBytes());
        os.close();
    }

    static class Customer {
        String id, name, email;
        Customer(String id, String name, String email) {
            this.id = id; this.name = name; this.email = email;
        }
        public String toString() {
            return String.format("Customer{id='%s', name='%s', email='%s'}", id, name, email);
        }
    }
}