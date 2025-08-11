import java.io.*;
import java.net.*;
import java.util.*;

class MLModelService {
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/predict", new PredictHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}

class PredictHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody()));
            String line;
            StringBuilder inputData = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                inputData.append(line);
            }
            
            // 模拟处理JSON输入
            String jsonInput = inputData.toString();
            String scriptName = extractScriptName(jsonInput);
            
            // 存在漏洞的命令执行
            String command = "python3 /models/" + scriptName + " --process";
            try {
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader procReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String procLine;
                while ((procLine = procReader.readLine()) != null) {
                    output.append(procLine);
                }
                String response = "Prediction result: " + output.toString();
                sendResponse(exchange, response);
            } catch (Exception e) {
                sendResponse(exchange, "Error: " + e.getMessage());
            }
        }
    }
    
    private String extractScriptName(String json) {
        // 简单模拟JSON解析
        int start = json.indexOf("scriptName") + 12;
        int end = json.indexOf("\\"", start + 1);
        return json.substring(start + 1, end);
    }
    
    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}