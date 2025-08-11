import java.io.*;
import java.net.*;
import java.util.*;

class ChatServer {
    private static final String FILE_COMMAND = "sendfile:";
    private static final Set<String> BLACKLIST = new HashSet<>(Arrays.asList(";", "&", "|", "\\\
"));

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new ClientHandler(clientSocket).start();
        }
    }

    static class ClientHandler extends Thread {
        private final Socket socket;
        private final BufferedReader in;
        private final PrintWriter out;

        public ClientHandler(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.out = new PrintWriter(socket.getOutputStream(), true);
        }

        @Override
        public void run() {
            try {
                String input;
                while ((input = in.readLine()) != null) {
                    if (input.startsWith(FILE_COMMAND)) {
                        String filename = input.substring(FILE_COMMAND.length());
                        if (validateInput(filename)) {
                            String command = "cat " + filename + " | nc -w 1 127.0.0.1 8080";
                            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
                            Process process = pb.start();
                            int exitCode = process.waitFor();
                            out.println("File transfer result: " + exitCode);
                        } else {
                            out.println("Invalid filename!");
                        }
                    } else {
                        System.out.println("Received: " + input);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private boolean validateInput(String input) {
            for (String badChar : BLACKLIST) {
                if (input.contains(badChar)) {
                    System.out.println("Found bad char: " + badChar);
                    return false;
                }
            }
            return true;
        }
    }
}