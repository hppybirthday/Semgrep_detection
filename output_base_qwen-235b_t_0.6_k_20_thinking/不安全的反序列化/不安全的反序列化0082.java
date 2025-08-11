import java.io.*;
import java.net.*;
import java.util.function.*;
import java.util.*;

public class ChatServer {
    static class Message implements Serializable {
        String content;
        public Message(String content) { this.content = content; }
    }

    public static void main(String[] args) {
        Function<Socket, Void> handler = socket -> {
            try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
                Object obj = ois.readObject();
                if (obj instanceof Message) {
                    System.out.println("Received: " + ((Message) obj).content);
                } else {
                    System.out.println("Unknown object type: " + obj.getClass());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        };

        try (ServerSocket server = new ServerSocket(8080)) {
            System.out.println("Server started on port 8080");
            while (true) {
                Socket socket = server.accept();
                new Thread(() -> handler.apply(socket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Vulnerable client code for demonstration:
// public class ChatClient {
//     public static void main(String[] args) throws Exception {
//         try (Socket socket = new Socket("localhost", 8080);
//              ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
//             Object payload = new ArrayList<>(Arrays.asList(
//                 Runtime.getRuntime(),
//                 "calc" // Simulated malicious payload
//             ));
//             oos.writeObject(payload);
//         }
//     }
// }