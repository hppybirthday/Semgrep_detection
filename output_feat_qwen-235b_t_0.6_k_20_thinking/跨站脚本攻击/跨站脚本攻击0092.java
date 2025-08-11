import java.io.*;
import java.net.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class MathModelServer {
    static List<ModelData> models = new ArrayList<>();

    static class ModelData {
        String name;
        String equation;
        ModelData(String name, String equation) {
            this.name = name;
            this.equation = equation;
        }
    }

    static class ReportGenerator {
        String generateReport(ModelData model) {
            return String.format("<html><body><h1>Model: %s</h1><p>Equation: %s</p></body></html>",
                model.name, model.equation);
        }
    }

    static class XSSAttackHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                String formData = br.readLine();
                
                Map<String, String> params = parseFormData(formData);
                ModelData model = new ModelData(
                    params.get("name"),
                    params.get("equation")
                );
                models.add(model);
                
                String response = new ReportGenerator().generateReport(model);
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
        
        private Map<String, String> parseFormData(String formData) {
            Map<String, String> params = new HashMap<>();
            for (String pair : formData.split("&")) {
                String[] entry = pair.split("=");
                params.put(entry[0], entry[1]);
            }
            return params;
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/submit", new XSSAttackHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}