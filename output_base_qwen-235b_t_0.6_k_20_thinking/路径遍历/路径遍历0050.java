import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

class ChatServer {
    private static final String BASE_DIR = "/var/chat_uploads/";

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Server started on port 8080");

        while (true) {
            Socket socket = serverSocket.accept();
            handleClient(socket);
        }
    }

    private static void handleClient(Socket socket) {
        try (BufferedReader in = new BufferedReader(
                 new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            String request = in.readLine();
            if (request == null || !request.startsWith("GET /file?path=")) {
                sendError(out, 400, "Bad Request");
                return;
            }

            // Extract file path from request
            String filePath = request.split(" ")[0].split("path=")[1];
            File file = new File(BASE_DIR + filePath);

            if (!file.exists()) {
                sendError(out, 404, "File Not Found");
                return;
            }

            // Read file content
            byte[] content = Files.readAllBytes(file.toPath());
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: application/octet-stream");
            out.println("Content-Length: " + content.length);
            out.println();
            out.flush();
            socket.getOutputStream().write(content);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendError(PrintWriter out, int code, String message) {
        out.println("HTTP/1.1 " + code + " " + message);
        out.println("Content-Type: text/plain");
        out.println();
        out.println(message);
    }
}