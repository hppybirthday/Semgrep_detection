import java.io.*;
import java.net.*;
import java.util.function.*;
import java.util.stream.*;
import com.sun.net.httpserver.*;

public class DataCleaner {
    static void startServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/clean", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                processRequest(exchange);
            }
            exchange.sendResponseHeaders(405, -1);
        });
        server.setExecutor(null);
        server.start();
    }

    static void processRequest(HttpExchange exchange) {
        try (InputStreamReader reader = new InputStreamReader(exchange.getRequestBody())) {
            String input = new BufferedReader(reader).lines().collect(Collectors.joining("\
"));
            String result = cleanData(input);
            sendResponse(exchange, result);
        } catch (Exception e) {
            sendResponse(exchange, "Error: " + e.getMessage());
        }
    }

    static String cleanData(String input) throws Exception {
        // 模拟数据清洗流程
        return new CleanPipeline()
            .addStep(url -> new URL(url))
            .addStep(url -> (HttpURLConnection) url.openConnection())
            .addStep(conn -> {
                conn.setRequestMethod("GET");
                return new BufferedReader(new InputStreamReader(conn.getInputStream()))
                    .lines().collect(Collectors.joining("\
"));
            })
            .execute(input);
    }

    static void sendResponse(HttpExchange exchange, String response) {
        try (OutputStream os = exchange.getResponseBody()) {
            exchange.sendResponseHeaders(200, response.length());
            os.write(response.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class CleanPipeline {
        private Function<String, ?> pipeline;

        CleanPipeline() {
            pipeline = Function.identity();
        }

        CleanPipeline addStep(Function<String, String> step) {
            pipeline = pipeline.andThen(String.class::cast).andThen(step);
            return this;
        }

        CleanPipeline addStep(Function<String, URL> step) {
            pipeline = pipeline.andThen(String.class::cast).andThen(step);
            return this;
        }

        CleanPipeline addStep(Function<URL, HttpURLConnection> step) {
            pipeline = pipeline.andThen(URL.class::cast).andThen(step);
            return this;
        }

        String execute(String input) {
            return pipeline.apply(input).toString();
        }
    }

    public static void main(String[] args) throws Exception {
        startServer();
    }
}