import java.io.*;
import java.net.*;
import java.nio.file.*;

class MLModelLoader {
    private static final String BASE_DIR = "/var/ml_models/";
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/loadModel", new ModelHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    static class ModelHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                    String query = exchange.getRequestURI().getQuery();
                    String filename = parseQueryParam(query, "filename");
                    
                    if (filename == null) {
                        sendResponse(exchange, 400, "Missing filename parameter");
                        return;
                    }

                    // Vulnerable path construction
                    Path modelPath = Paths.get(BASE_DIR + filename);
                    
                    // Simulate model loading
                    if (!Files.exists(modelPath)) {
                        sendResponse(exchange, 404, "Model not found: " + filename);
                        return;
                    }

                    // Read model file (vulnerable to path traversal)
                    StringBuilder content = new StringBuilder();
                    try (BufferedReader reader = Files.newBufferedReader(modelPath)) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            content.append(line).append("\
");
                        }
                    }

                    sendResponse(exchange, 200, "Model content:\
" + content.toString());
                }
            } catch (Exception e) {
                sendResponse(exchange, 500, "Server error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        private String parseQueryParam(String query, String paramName) {
            if (query == null) return null;
            return java.util.Arrays.stream(query.split("&"))
                .filter(s -> s.startsWith(paramName + "="))
                .map(s -> s.substring(paramName.length() + 1))
                .findFirst()
                .orElse(null);
        }

        private void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
            exchange.sendResponseHeaders(code, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }
}