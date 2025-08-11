import java.io.*;
import java.net.*;
import java.util.*;
import java.util.function.*;

class ChatServer {
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
        private final Map<String, Consumer<String[]>> commands = new HashMap<>();

        public ClientHandler(Socket socket) {
            this.socket = socket;
            registerCommands();
        }

        private void registerCommands() {
            commands.put("!ping", (args) -> executeCommand("ping " + args[0]));
            commands.put("!tracert", (args) -> executeCommand("tracert " + args[0]));
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(
                     new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                out.println("Connected to chat server");
                String input;

                while ((input = in.readLine()) != null) {
                    if (input.startsWith("!")) {
                        String[] parts = input.split(" ", 2);
                        String cmd = parts[0];
                        String[] args = parts.length > 1 ? new String[]{parts[1]} : new String[0];

                        commands.getOrDefault(cmd, (a) -> out.println("Unknown command"))
                               .accept(args);
                    } else {
                        System.out.println("Received message: " + input);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void executeCommand(String command) {
            try {
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}