import java.io.*;
import com.sun.net.httpserver.*;
import java.net.InetSocketAddress;

public class DeviceServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/getLog", (HttpExchange exchange) -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                String query = exchange.getRequestURI().getQuery();
                String filename = query.split("=")[1];
                File file = new File("logs/" + filename);
                if (file.exists()) {
                    String response = readFile(file);
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } else {
                    exchange.sendResponseHeaders(404, 0);
                }
            } else {
                exchange.sendResponseHeaders(405, 0);
            }
        });
        server.setExecutor(null);
        server.start();
    }

    private static String readFile(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            content.append(line).append("\
");
        }
        br.close();
        return content.toString();
    }
}