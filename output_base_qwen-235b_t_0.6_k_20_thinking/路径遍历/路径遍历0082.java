import java.io.*;
import java.net.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

class ChatServer {
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/chatlog", (exchange) -> {
            try {
                String query = exchange.getRequestURI().getQuery();
                String username = Optional.ofNullable(query)
                    .map(q -> q.split("=", 2))
                    .filter(p -> p.length == 2 && p[0].equals("user"))
                    .map(p -> p[1])
                    .orElseThrow(() -> new IllegalArgumentException("Invalid user parameter"));

                // Vulnerable path construction
                String filePath = "logs/" + username + ".log";
                File file = new File(filePath);

                if (!file.exists()) {
                    exchange.sendResponseHeaders(404, 0);
                    return;
                }

                // Read file content
                String content = new BufferedReader(new FileReader(file))
                    .lines()
                    .collect(Collectors.joining("\
"));

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, content.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(content.getBytes());
                }
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, 0);
            } finally {
                exchange.close();
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8080");
    }
}