import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.util.Map;
import com.google.gson.Gson;

public class SimulationCommandServer extends WebSocketServer {
    public SimulationCommandServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        conn.send("Connected to simulation command server");
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Client disconnected");
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        try {
            Gson gson = new Gson();
            Map<String, String> params = gson.fromJson(message, Map.class);
            
            String user = params.get("user");
            String password = params.get("password");
            String db = params.get("db");
            
            // Vulnerable command construction
            String command = "run_simulation.sh " + user + " " + password + " " + db;
            
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            conn.send("Simulation output: " + output.toString());
            
        } catch (Exception e) {
            conn.send("Error executing command: " + e.getMessage());
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("Server started on port 8080");
    }

    public static void main(String[] args) {
        SimulationCommandServer server = new SimulationCommandServer(8080);
        server.start();
    }
}