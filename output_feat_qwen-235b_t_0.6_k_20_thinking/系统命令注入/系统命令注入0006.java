import java.io.*;
import java.util.*;
import com.sun.net.httpserver.*;

class IoTDeviceController {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api/control", new DeviceControlHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("IoT Controller started on port 8080");
    }

    static class DeviceControlHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                
                if (params.containsKey("command")) {
                    String command = params.get("command");
                    String response = executeCommand(command);
                    sendResponse(exchange, 200, response);
                } else {
                    sendResponse(exchange, 400, "Missing command parameter");
                }
            } catch (Exception e) {
                sendResponse(exchange, 500, "Internal server error");
            }
        }

        private String executeCommand(String command) throws IOException {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "iot_ctl " + command);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            
            return output.toString();
        }

        private void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
            exchange.sendResponseHeaders(code, response.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

        private Map<String, String> parseQuery(String query) {
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
}