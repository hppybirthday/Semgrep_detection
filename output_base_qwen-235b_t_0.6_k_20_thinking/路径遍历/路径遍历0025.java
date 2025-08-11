import java.io.*;
import java.net.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class LogProcessor {
    private static final String BASE_DIR = "/var/logs/bigdata/";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/process", new LogHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class LogHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                
                String logPath = params.get("path");
                String fullPath = BASE_DIR + logPath;
                
                File file = new File(fullPath);
                if (!file.exists()) {
                    sendResponse(exchange, 404, "File not found");
                    return;
                }

                String content = readFileContent(file);
                sendResponse(exchange, 200, content);
                
            } catch (Exception e) {
                sendResponse(exchange, 500, "Internal error");
                e.printStackTrace();
            }
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> result = new HashMap<>();
            if (query == null) return result;
            
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                if (entry.length > 1) {
                    result.put(entry[0], entry[1]);
                }
            }
            return result;
        }

        private String readFileContent(File file) throws IOException {
            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\
");
                }
            }
            return content.toString();
        }

        private void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
            exchange.sendResponseHeaders(code, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }
}