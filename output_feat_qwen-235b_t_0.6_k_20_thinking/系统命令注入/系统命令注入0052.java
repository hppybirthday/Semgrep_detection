import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.function.*;

public class VulnerableWebApp {
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/upload", (HttpExchange exchange) -> {
            try {
                if ("POST".equals(exchange.getRequestMethod())) {
                    String filename = parseFilename(exchange);
                    String response = handleFileUpload(filename);
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        server.setExecutor(null);
        server.start();
    }

    private static String parseFilename(HttpExchange exchange) {
        return exchange.getRequestHeaders().get("X-Filename").get(0);
    }

    private static String handleFileUpload(String filename) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String[] cmd;
            if (os.contains("win")) {
                cmd = new String[]{"cmd.exe", "/C", "type " + filename};
            } else {
                cmd = new String[]{"sh", "-c", "file " + filename};
            }
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            reader.lines().forEach(output::append);
            return "File info: " + output.toString();
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }
}