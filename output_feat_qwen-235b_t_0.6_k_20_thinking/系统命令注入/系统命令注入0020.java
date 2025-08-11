import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.CopyOnWriteArraySet;

@ServerEndpoint("/command")
public class CommandEndpoint {
    private static final CopyOnWriteArraySet<Session> sessions = new CopyOnWriteArraySet<>();

    @OnOpen
    public void onOpen(Session session) {
        sessions.add(session);
    }

    @OnMessage
    public void onMessage(String message, Session session) {
        try {
            // Simulate JSON parsing from client message
            String hostname = parseHostnameFromJson(message);
            
            // Vulnerable command construction
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "nslookup " + hostname);
            Process process = pb.start();
            
            // Read command output
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // Send response back to client
            session.getBasicRemote().sendText("Command output:\
" + output.toString());
            
        } catch (Exception e) {
            try {
                session.getBasicRemote().sendText("Error executing command: " + e.getMessage());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            e.printStackTrace();
        }
    }

    @OnClose
    public void onClose(Session session) {
        sessions.remove(session);
    }

    // Simulated JSON parser with vulnerable parameter extraction
    private String parseHostnameFromJson(String json) {
        // In a real scenario would use proper JSON parsing
        // This simulates extracting {"hostname":"user_input"} from JSON
        return json.split("\\\\"")[3];
    }
}