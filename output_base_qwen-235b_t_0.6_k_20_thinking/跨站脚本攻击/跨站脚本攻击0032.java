import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

class XSSFileEncryptor {
    static final String ENCRYPTION_KEY = "secret123";
    
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/encrypt", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                handleGet(exchange);
            } else {
                handlePost(exchange);
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static void handleGet(HttpExchange exchange) throws IOException {
        String response = "<html><body>\
" +
            "<h2>File Encryptor</h2>\
" +
            "<form method=POST enctype=multipart/form-data>\
" +
            "File: <input type=file name=file><br>\
" +
            "Password: <input type=password name=password><br>\
" +
            "<input type=submit value=Encrypt>\
" +
            "</form></body></html>";
        sendResponse(exchange, response);
    }

    static void handlePost(HttpExchange exchange) throws IOException {
        try {
            Map<String, String> params = parseFormData(exchange);
            String fileName = params.get("file");
            String password = params.get("password");
            
            // Vulnerable: Directly using user input in HTML response
            String encryptedName = encrypt(fileName, password);
            
            String response = String.format(
                "<html><body>\
" +
                "<h3>Encrypted File:</h3>\
" +
                "<a href='/download?file=%s'>Download %s</a>\
" +
                "</body></html>",
                encryptedName, fileName // Vulnerable point here
            );
            
            sendResponse(exchange, response);
        } catch (Exception e) {
            sendResponse(exchange, "<span style=color:red>Error: " + e.getMessage() + "</span>");
        }
    }

    static String encrypt(String data, String key) {
        // Simplified encryption for demo purposes
        return Base64.getEncoder().encodeToString(
            data.getBytes() ^ key.getBytes()
        );
    }

    static Map<String, String> parseFormData(HttpExchange exchange) throws IOException {
        Map<String, String> result = new HashMap<>();
        Headers headers = exchange.getRequestHeaders();
        if (headers.containsKey("Content-Type")) {
            String boundary = headers.getFirst("Content-Type").split("boundary=")[1].split(",")[0];
            BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("filename=")) {
                    String name = line.split("name=\\"")[1].split("")[0];
                    String filename = line.split("filename=\\"")[1].split("")[0];
                    result.put(name, filename);
                } else if (line.contains("name=")) {
                    String name = line.split("name=\\"")[1].split("")[0];
                    String value = reader.readLine();
                    result.put(name, value);
                }
            }
        }
        return result;
    }

    static void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}