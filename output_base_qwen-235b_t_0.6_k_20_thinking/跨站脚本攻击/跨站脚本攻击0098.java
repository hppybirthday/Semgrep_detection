import java.io.*;
import java.net.*;
import java.util.*;

class ChatServer {
    static List<PrintWriter> clients = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        while (true) {
            Socket s = ss.accept();
            new Thread(() -> {
                try (
                    BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                    PrintWriter out = new PrintWriter(s.getOutputStream(), true);
                ) {
                    clients.add(out);
                    String msg;
                    while ((msg = in.readLine()) != null) {
                        System.out.println("Received: " + msg);
                        clients.forEach(client -> client.println(msg));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
}

class ChatClient {
    public static void main(String[] args) throws Exception {
        Socket s = new Socket("localhost", 8080);
        new Thread(() -> {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()))) {
                String line;
                while ((line = in.readLine()) != null) {
                    System.out.println("[Message] " + line);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        try (BufferedReader console = new BufferedReader(new InputStreamReader(System.in))) {
            String input;
            while ((input = console.readLine()) != null) {
                try (OutputStream out = s.getOutputStream()) {
                    out.write((input + "\
").getBytes());
                    out.flush();
                }
            }
        }
    }
}