import java.io.*;
import java.net.*;
import com.sun.net.httpserver.*;

class ChatFileServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/download", new FileHandler());
        server.setExecutor(null);
        server.start();
    }

    static class FileHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                StringBuilder json = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) json.append(line);

                String src = json.toString().split("\\"src\\":\\"")[1].split("\\"")[0];
                String srcB = json.toString().split("\\"srcB\\":\\"")[1].split("\\"")[0];

                try {
                    URL url = new URL(src);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");

                    BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder content = new StringBuilder();
                    String inputLine;
                    while ((inputLine = in.readLine()) != null) content.append(inputLine);
                    in.close();

                    URL urlB = new URL(srcB);
                    BufferedReader inB = new BufferedReader(new InputStreamReader(urlB.openStream()));
                    StringBuilder contentB = new StringBuilder();
                    String inputLineB;
                    while ((inputLineB = inB.readLine()) != null) contentB.append(inputLineB);
                    inB.close();

                    String response = "{\\"fileA\\":\\"" + content.toString() + "\\",\\"fileB\\":\\"" + contentB.toString() + "\\"}";
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    exchange.sendResponseHeaders(500, 0);
                    exchange.getResponseBody().close();
                }
            }
        }
    }
}