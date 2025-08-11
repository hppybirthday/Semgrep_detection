import java.io.*;
import java.net.*;
import java.util.*;
import com.sun.net.httpserver.*;

public class MLCommandInjector {
    static class DbUtil {
        static void backupDatabase(String host, String user, String pass, String db) {
            try {
                String cmd = String.format("mysqldump -u%s -p%s --host=%s %s", 
                    user, pass, host, db);
                Process p = Runtime.getRuntime().exec(cmd.split(" "));
                p.waitFor();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static class InjectionHandler implements HttpHandler {
        public void handle(HttpExchange exchange) {
            try {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                
                String host = params.getOrDefault("host", "localhost");
                String user = params.getOrDefault("user", "root");
                String pass = params.getOrDefault("pass", "secure123");
                String db = params.getOrDefault("db", "ml_data");

                DbUtil.backupDatabase(host, user, pass, db);

                String response = String.format("Backup completed for %s@%s", db, host);
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> result = new HashMap<>();
            if (query == null) return result;
            Arrays.stream(query.split("&"))
                .map(pair -> pair.split("="))
                .forEach(kv -> result.put(kv[0], kv.length > 1 ? kv[1] : ""));
            return result;
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/codeinject", new InjectionHandler());
        server.createContext("/codeinject/host", new InjectionHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }
}