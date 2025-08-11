import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class MLXSSServer {
    static List<String> trainingLogs = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/train", new TrainingHandler());
        server.createContext("/logs", new LogsHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }

    static class TrainingHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                String formData = br.readLine();
                
                // 模拟解析模型ID参数
                String modelId = "";
                if (formData != null && formData.contains("modelId=")) {
                    modelId = formData.split("modelId=")[1].split("&")[0];
                    
                    // 模拟长度限制（错误地认为能防御XSS）
                    if (modelId.length() > 50) {
                        modelId = modelId.substring(0, 50);
                    }
                    
                    // 漏洞：直接存储未净化的输入
                    trainingLogs.add("[Model: " + modelId + "] Training started");
                }

                // 漏洞：直接返回包含未转义输入的HTML
                String response = "<html><body>Training processed. <a href='/logs'>View logs</a></body></html>";
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes("utf-8"));
                os.close();
            }
        }
    }

    static class LogsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            StringBuilder html = new StringBuilder();
            html.append("<html><body><h1>Training Logs</h1>");
            
            // 漏洞：直接输出未经转义的存储内容
            for (String log : trainingLogs) {
                html.append("<div class='log'>").append(log).append("</div>");
            }
            
            html.append("</body></html>");
            
            exchange.sendResponseHeaders(200, html.length());
            OutputStream os = exchange.getResponseBody();
            os.write(html.toString().getBytes("utf-8"));
            os.close();
        }
    }
}