import java.io.*;
import java.net.*;
import java.util.*;

class MLServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/predict", new PredictHandler());
        server.setExecutor(null);
        server.start();
    }
}

class PredictHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            String input = exchange.getRequestURI().getQuery().split("=")[1];
            String response = "<html><body><h1>ML Prediction</h1>"
                + "<p>Predicted value for: " + input + " = " + predict(input) + "</p>"
                + "<a href=\\"/\\">Try again</a></body></html>";
            sendResponse(exchange, response);
        } else {
            sendResponse(exchange, "<html><form action=/predict>Input:<input name=input><input type=submit></form></html>");
        }
    }

    private String predict(String input) {
        return String.valueOf(input.length() * 42); // Mock ML prediction
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}