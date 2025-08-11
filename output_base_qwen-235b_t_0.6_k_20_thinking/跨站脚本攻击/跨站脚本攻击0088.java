import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class MLXSSServer {
    static class PredictHandler implements HttpHandler {
        public void handle(HttpExchange t) throws IOException {
            if (t.getRequestMethod().equalsIgnoreCase("POST")) {
                InputStreamReader isr = new InputStreamReader(t.getRequestBody(), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                String query = br.lines().reduce("", String::concat);
                
                Map<String, String> params = parseQuery(query);
                String userInput = params.get("text");
                
                String response = "<html><body><h1>预测结果</h1>\
" +
                    "<p>您输入的文本: " + userInput + "</p>\
" +
                    "<p>分类标签: " + classifyText(userInput) + "</p>\
" +
                    "<a href='/'>返回</a></body></html>";
                
                t.sendResponseHeaders(200, response.length());
                OutputStream os = t.getResponseBody();
                os.write(response.getBytes("utf-8"));
                os.close();
            }
        }
        
        private Map<String, String> parseQuery(String query) {
            Map<String, String> result = new HashMap<>();
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                result.put(entry[0], entry.length > 1 ? entry[1] : "");
            }
            return result;
        }
        
        private String classifyText(String text) {
            return text.contains("malware") ? "恶意" : "正常";
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/predict", new PredictHandler());
        server.createContext("/", new HttpHandler() {
            public void handle(HttpExchange t) throws IOException {
                String form = "<html><body><form method='POST' action='/predict'>\
" +
                    "<textarea name='text'></textarea><br>\
" +
                    "<input type='submit' value='分类'>\
" +
                    "</form></body></html>";
                t.sendResponseHeaders(200, form.length());
                OutputStream os = t.getResponseBody();
                os.write(form.getBytes("utf-8"));
                os.close();
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}