import java.io.*;
import java.net.*;

class ChatServer {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8888);
        while (true) {
            Socket s = ss.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            String cmd = in.readLine();
            if (cmd.startsWith("/view")) {
                String file = cmd.split(" ")[1];
                FileReader fr = new FileReader("/var/chat/logs/" + file);
                BufferedReader br = new BufferedReader(fr);
                String line;
                while ((line = br.readLine()) != null) {
                    System.out.println(line);
                }
                br.close();
            }
            s.close();
        }
    }
}

class ChatClient {
    public static void main(String[] args) throws Exception {
        Socket s = new Socket("localhost", 8888);
        PrintWriter out = new PrintWriter(s.getOutputStream(), true);
        out.println("/view ../../etc/passwd");
        s.close();
    }
}