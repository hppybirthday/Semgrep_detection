import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.*;

class ChatServer {
    private static final int PORT = 9090;
    private static final ExecutorService clientHandlers = Executors.newCachedThreadPool();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Chat server started on port " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                clientHandlers.submit(() -> handleClient(clientSocket));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                if (inputLine.startsWith("!run")) {
                    String command = inputLine.substring(4).trim();
                    String result = CommandExecutor.executeCommand(command);
                    out.println("[COMMAND_RESULT]: " + result);
                } else {
                    System.out.println("Received: " + inputLine);
                    out.println("Echo: " + inputLine);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class CommandExecutor {
    public static String executeCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"sh", "-c", "echo \\"Executing: " + command + "\\" && " + command}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return "Exit code: " + exitCode + "\
Output:\
" + output.toString();
            
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

/*
Vulnerable usage example:
1. Connect with telnet: telnet localhost 9090
2. Send: !run ls -la /tmp
3. Attack: !run cat /etc/passwd; rm -rf /
*/