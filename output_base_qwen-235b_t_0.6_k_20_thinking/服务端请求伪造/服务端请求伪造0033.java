import java.io.*;
import java.net.*;
import com.sun.net.httpserver.*;

class Crawler {
    public String fetch(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        conn.disconnect();
        return content.toString();
    }
}

class CrawlerHandler implements HttpHandler {
    private Crawler crawler = new Crawler();
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String query = exchange.getRequestURI().getQuery();
            String[] params = query.split("=");
            
            if (params.length < 2 || !params[0].equals("url")) {
                String response = "Usage: /crawl?url=<url>";
                exchange.sendResponseHeaders(400, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
                return;
            }
            
            String targetUrl = URLDecoder.decode(params[1], "UTF-8");
            String result = crawler.fetch(targetUrl);
            
            exchange.sendResponseHeaders(200, result.length());
            OutputStream os = exchange.getResponseBody();
            os.write(result.getBytes());
            os.close();
            
        } catch (Exception e) {
            String response = "Error: " + e.getMessage();
            exchange.sendResponseHeaders(500, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}

public class VulnerableCrawlerServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/crawl", new CrawlerHandler());
        server.setExecutor(null);
        System.out.println("Server started on port 8000");
        server.start();
    }
}