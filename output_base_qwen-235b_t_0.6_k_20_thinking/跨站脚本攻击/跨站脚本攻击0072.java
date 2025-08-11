import java.io.*;
import java.net.*;
import java.util.*;
import java.util.function.*;
import java.nio.charset.*;
import com.sun.net.httpserver.*;

public class MLXSSDemo {
    static class SentimentPredictor {
        static String predictSentiment(String text) {
            // 模拟机器学习预测逻辑
            return text.contains("happy") ? "Positive" : "Negative";
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/predict", new HttpHandler() {
            public void handle(HttpExchange exchange) {
                try {
                    if ("POST".equals(exchange.getRequestMethod())) {
                        InputStream is = exchange.getRequestBody();
                        String body = new BufferedReader(new InputStreamReader(is))
                            .lines().reduce("", (acc, line) -> acc + line);
                        
                        Map<String, String> params = parseQuery(body);
                        String userInput = params.get("text");
                        
                        // 漏洞点：直接将用户输入嵌入HTML输出
                        String response = "<html><body>\
" +
                            "<h2>Prediction Result</h2>\
" +
                            "<p>Input Text: " + userInput + "</p>\
" +
                            "<p>Sentiment: " + SentimentPredictor.predictSentiment(userInput) + "</p>\
" +
                            "<a href=\\"/\\">Back</a>\
" +
                            "</body></html>";
                        
                        sendResponse(exchange, response);
                    } else {
                        sendResponse(exchange, getFormHTML());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on http://localhost:8000");
    }
    
    static String getFormHTML() {
        return "<html><body>\
" +
               "<h2>Sentiment Analysis</h2>\
" +
               "<form method=\\"POST\\" action=\\"/predict\\">\
" +
               "<textarea name=\\"text\\"></textarea><br>\
" +
               "<input type=\\"submit\\" value=\\"Analyze\\">\
" +
               "</form></body></html>";
    }
    
    static void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }
    
    static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        Arrays.stream(query.split("&"))
            .map(pair -> pair.split("="))
            .forEach(parts -> result.put(decode(parts[0]), decode(parts[1])));
        return result;
    }
    
    static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}