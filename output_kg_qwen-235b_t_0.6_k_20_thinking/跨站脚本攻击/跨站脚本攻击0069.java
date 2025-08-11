import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class XSSVulnerableApp {
    static class DataCleaner {
        // 模拟不安全的数据清洗方法
        public String cleanInput(String input) {
            // 错误地认为替换<script>标签就足够
            return input.replaceAll("(?i)<script>", "").replaceAll("(?i)</script>", "");
        }
    }

    static class XSSVulnerableHandler implements HttpHandler {
        private final DataCleaner cleaner = new DataCleaner();

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "";
            if ("GET".equals(exchange.getRequestMethod())) {
                response = getForm();
            } else if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostBody(exchange);
                String userInput = params.get("content");
                String cleaned = cleaner.cleanInput(userInput);
                response = getResponsePage(cleaned);
            }

            exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes(StandardCharsets.UTF_8));
            }
        }

        private String getForm() {
            return "<html><body><form method='post'>" +
                   "输入内容：<br><textarea name='content' rows='4' cols='50'></textarea><br>" +
                   "<input type='submit' value='提交'>" +
                   "</form></body></html>";
        }

        private String getResponsePage(String content) {
            return "<html><body><h3>清洗后内容：</h3><div>" +
                   content + "</div><br><a href='/'>返回</a></body></html>";
        }

        private Map<String, String> parsePostBody(HttpExchange exchange) throws IOException {
            InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(isr);
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
            Map<String, String> params = new HashMap<>();
            for (String param : body.toString().split("&")) {
                String[] pair = param.split("=");
                if (pair.length == 2) {
                    params.put(pair[0], URLDecoder.decode(pair[1], "UTF-8"));
                }
            }
            return params;
        }
    }

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", new XSSVulnerableHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("服务器已启动，访问 http://localhost:8000");
    }
}