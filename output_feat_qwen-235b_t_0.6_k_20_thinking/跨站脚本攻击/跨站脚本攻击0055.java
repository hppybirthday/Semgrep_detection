import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

public class GameServer {
    public static List<String> messages = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        
        // 漏洞点1：未校验用户输入的回调参数
        server.createContext("/submit", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "UTF-8");
                    BufferedReader br = new BufferedReader(isr);
                    String formData = br.readLine();
                    Map<String, String> params = parseFormData(formData);
                    
                    String message = params.get("message");
                    if (message != null && !message.isEmpty()) {
                        // 漏洞点2：直接存储用户输入内容
                        messages.add(message);
                    }
                    
                    String response = "Message submitted successfully";
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    String response = "Error processing request";
                    exchange.sendResponseHeaders(500, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });
        
        server.createContext("/", exchange -> {
            String html = generateMessagesPage();
            exchange.sendResponseHeaders(200, html.length());
            OutputStream os = exchange.getResponseBody();
            os.write(html.getBytes());
            os.close();
        });
        
        server.setExecutor(null);
        server.start();
        System.out.println("Game server started on port 8080");
    }
    
    private static Map<String, String> parseFormData(String formData) {
        Map<String, String> params = new HashMap<>();
        if (formData != null && !formData.isEmpty()) {
            Arrays.stream(formData.split("&"))
                .map(pair -> pair.split("="))
                .forEach(parts -> {
                    try {
                        String key = java.net.URLDecoder.decode(parts[0], "UTF-8");
                        String value = (parts.length > 1) ? java.net.URLDecoder.decode(parts[1], "UTF-8") : "";
                        params.put(key, value);
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                });
        }
        return params;
    }
    
    private static String generateMessagesPage() {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><title>Game Messages</title></head><body>")
            .append("<h1>Player Messages</h1>")
            .append("<ul>");
        
        for (String msg : messages) {
            // 漏洞点3：未对用户输入进行HTML转义
            html.append("<li>").append(msg).append("</li>");
        }
        
        html.append("</ul>")
            .append("<h2>Send Message</h2>")
            .append("<form method='POST' action='/submit'>")
            .append("<textarea name='message'></textarea>")
            .append("<br><button type='submit'>Send</button>")
            .append("</form>")
            .append("</body></html>");
        
        return html.toString();
    }
}