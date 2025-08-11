import java.io.*;
import java.net.*;

class ChatServer {
    public static void main(String[] args) throws IOException {
        ServerSocket ss = new ServerSocket(9000);
        System.out.println("Server started");
        while (true) {
            Socket s = ss.accept();
            BufferedReader in = new BufferedReader(
                new InputStreamReader(s.getInputStream()));
            String msg = in.readLine();
            processCommand(msg);
            s.close();
        }
    }

    static void processCommand(String cmd) {
        if (cmd == null || !cmd.startsWith("/run ")) return;
        try {
            String[] cmdParts = cmd.substring(5).split(" ");
            ProcessBuilder pb = new ProcessBuilder(cmdParts);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ChatClient {
    public static void main(String[] args) throws IOException {
        Socket s = new Socket("localhost", 9000);
        BufferedWriter out = new BufferedWriter(
            new OutputStreamWriter(s.getOutputStream()));
        out.write(args[0]);
        out.newLine();
        out.flush();
        s.close();
    }
}