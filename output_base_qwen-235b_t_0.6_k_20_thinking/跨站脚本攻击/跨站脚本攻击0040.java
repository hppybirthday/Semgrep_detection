import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

public class MLModelServer {
    static class XSSVulnerableHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                InputStream is = exchange.getRequestBody();
                String formData = readInputStream(is);
                Map<String, String> params = parseFormData(formData);
                
                // 漏洞点：直接将用户输入拼接到HTML中
                String modelName = params.get("model_name");
                String response = "<html><body><h2>模型训练结果 - " + modelName + "</h2>" +
                    "<p>训练参数: " + params.get("parameters") + "</p>" +
                    "<script>document.write('用户名: '+document.cookie)</script>" +
                    "</body></html>";
                
                exchange.getResponseHeaders().set("Content-Type", "text/html");
                exchange.sendResponseHeaders(200, response.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } else {
                String response = "<html><body>" +
                    "<form method=POST action=/train>" +
                    "模型名称: <input type=text name=model_name><br>" +
                    "参数配置: <input type=text name=parameters><br>" +
                    "<input type=submit value='训练模型'>" +
                    "</form></body></html>";
                exchange.getResponseHeaders().set("Content-Type", "text/html");
                exchange.sendResponseHeaders(200, response.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
        
        private String readInputStream(InputStream is) throws IOException {
            StringBuilder sb = new StringBuilder();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
        
        private Map<String, String> parseFormData(String formData) {
            Map<String, String> params = new HashMap<>();
            for (String pair : formData.split("&")) {
                String[] keyValue = pair.split("=");
                if (keyValue.length == 2) {
                    params.put(keyValue[0], keyValue[1]);
                }
            }
            return params;
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/train", new XSSVulnerableHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("服务器启动在 http://localhost:8000/train");
    }
}