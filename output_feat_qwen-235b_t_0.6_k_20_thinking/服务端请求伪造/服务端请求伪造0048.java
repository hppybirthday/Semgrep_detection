import java.io.*;
import java.net.*;
import com.sun.net.httpserver.*;

class SSRFDemo {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/encrypt", new EncryptHandler());
        server.setExecutor(null);
        server.start();
    }

    static class EncryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String query = exchange.getRequestURI().getQuery();
                String logId = parseLogId(query);
                
                URL url = new URL("https://internal-encryptor.example.com/encrypt?file=" + logId);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                
                InputStream is = conn.getInputStream();
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = is.read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                
                String response = "Encrypted: " + result.toString("UTF-8");
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
                
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, 0);
                exchange.getResponseBody().close();
            }
        }
        
        String parseLogId(String query) {
            if (query == null) return "";
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                String[] kv = pair.split("=");
                if (kv[0].equals("logId")) {
                    try {
                        return URLDecoder.decode(kv[1], "UTF-8");
                    } catch (UnsupportedEncodingException e) {}
                }
            }
            return "";
        }
    }
}