import java.io.*;
import java.net.*;
import com.sun.net.httpserver.*;

public class CRMFileServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/download", new DownloadHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class DownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String query = exchange.getRequestURI().getQuery();
                String fileName = "default.txt";
                
                if (query != null && query.startsWith("file=")) {
                    fileName = query.substring(5);
                }

                String baseDir = "/var/crm/files/";
                File file = new File(baseDir + fileName);
                
                if (file.exists()) {
                    byte[] fileBytes = readBytesFromFile(file);
                    exchange.sendResponseHeaders(200, fileBytes.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(fileBytes);
                    os.close();
                } else {
                    String response = "File not found";
                    exchange.sendResponseHeaders(404, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private byte[] readBytesFromFile(File file) throws IOException {
            FileInputStream fileInputStream = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fileInputStream.read(data);
            fileInputStream.close();
            return data;
        }
    }
}