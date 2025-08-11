import java.io.*;
import java.net.*;
import java.util.*;

public class ChatServer {
    private static final String BASE_DIR = "./data/";

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Server started on port 8080");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new ClientHandler(clientSocket).start();
        }
    }

    static class ClientHandler extends Thread {
        private final Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(
                     new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    if (inputLine.startsWith("VIEW_HISTORY")) {
                        String[] parts = inputLine.split(" ");
                        if (parts.length == 2) {
                            String chatRoom = parts[1];
                            String content = readChatHistory(chatRoom);
                            out.println("HISTORY_CONTENT|" + content);
                        }
                    } else if (inputLine.equals("EXIT")) {
                        break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private String readChatHistory(String chatRoom) {
            StringBuilder content = new StringBuilder();
            try {
                File file = new File(BASE_DIR + chatRoom + ".log");
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\
");
                }
                reader.close();
            } catch (IOException e) {
                content.append("[ERROR: Could not read history]");
            }
            return content.toString();
        }
    }
}