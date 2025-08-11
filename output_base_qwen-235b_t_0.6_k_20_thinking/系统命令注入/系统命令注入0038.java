import java.io.*;
import java.net.*;

class IoTController {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/getSensorData", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            String sensorId = "default";
            if (query != null && query.contains("sensorId=")) {
                sensorId = query.split("sensorId=")[1].split("&")[0];
            }
            
            String cmd = "cat /sensor/data/" + sensorId;
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder response = new StringBuilder();
            
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\
");
            }
            
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.toString().getBytes());
            os.close();
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}