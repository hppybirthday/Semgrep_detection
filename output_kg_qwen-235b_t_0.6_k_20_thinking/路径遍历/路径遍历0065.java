import java.io.*;
import java.net.*;
import java.util.*;

public class ChatFileServer {
    private static final String BASE_DIR = "/var/www/chat_uploads/";

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
            try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream())
            ) {
                String inputLine;
                String fileName = null;

                while ((inputLine = in.readLine()) != null) {
                    if (inputLine.startsWith("GET")) {
                        fileName = extractFileName(inputLine);
                    }
                    if (inputLine.isEmpty()) {
                        break;
                    }
                }

                if (fileName != null) {
                    File file = new File(BASE_DIR + fileName);
                    if (file.exists()) {
                        sendFileResponse(out, dataOut, file);
                    } else {
                        sendErrorResponse(out, 404, "File not found");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private String extractFileName(String getRequest) {
            String[] parts = getRequest.split(" ");
            if (parts.length > 1) {
                String query = parts[1];
                if (query.contains("?file=")) {
                    return query.split("\\\\?file=")[1].split(" ")[0];
                }
            }
            return "index.html";
        }

        private void sendFileResponse(PrintWriter out, DataOutputStream dataOut, File file) throws IOException {
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: application/octet-stream");
            out.println("Content-Length: " + file.length());
            out.println();
            out.flush();

            try (FileInputStream fileIn = new FileInputStream(file)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fileIn.read(buffer)) != -1) {
                    dataOut.write(buffer, 0, bytesRead);
                }
            }
        }

        private void sendErrorResponse(PrintWriter out, int code, String message) {
            out.println("HTTP/1.1 " + code + " " + message);
            out.println("Content-Type: text/plain");
            out.println();
            out.println(message);
        }
    }
}