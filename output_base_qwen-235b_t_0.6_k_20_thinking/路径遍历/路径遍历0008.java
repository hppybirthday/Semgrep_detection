import java.io.*;
import java.net.*;
import java.util.*;

class MLServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/predict", (exchange) -> {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
                String modelId = params.get("model");
                
                File model = new File("./models/" + modelId + ".bin");
                
                if (model.exists()) {
                    byte[] data = new byte[(int) model.length()];
                    new FileInputStream(model).read(data);
                    exchange.sendResponseHeaders(200, 0);
                    exchange.getResponseBody().write(data);
                } else {
                    exchange.sendResponseHeaders(404, 0);
                    exchange.getResponseBody().write("Model not found".getBytes());
                }
                exchange.getResponseBody().close();
            }
        });
        server.setExecutor(null);
        server.start();
    }

    static Map<String, String> queryToMap(String query) {
        Map<String, String> result = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                if (entry.length > 1) {
                    result.put(entry[0], entry[1]);
                }
            }
        }
        return result;
    }
}