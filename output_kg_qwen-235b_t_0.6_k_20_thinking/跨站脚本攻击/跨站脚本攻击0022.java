import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class GameServer {
    private static final List<ClientHandler> clients = new ArrayList<>();
    
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Game server started on port 8080");
            while (true) {
                Socket socket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(socket);
                clients.add(clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler implements Runnable {
        private final Socket socket;
        private BufferedReader reader;
        private PrintWriter writer;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                writer = new PrintWriter(socket.getOutputStream(), true);
                
                String username = reader.readLine();
                String welcomeMessage = MessageRenderer.createWelcomeMessage(username);
                broadcast(username + " joined the game", welcomeMessage);

                String input;
                while ((input = reader.readLine()) != null) {
                    String safeInput = input.replaceAll("[\\r\
]+", " ");
                    String htmlMessage = MessageRenderer.createChatMessage(username, safeInput);
                    broadcast(username + ": " + safeInput, htmlMessage);
                }
            } catch (IOException e) {
                System.out.println("Client disconnected: " + socket);
            } finally {
                clients.remove(this);
                try {
                    socket.close();
                } catch (IOException e) {}
            }
        }

        private void broadcast(String consoleMessage, String htmlMessage) {
            System.out.println(consoleMessage);
            for (ClientHandler client : clients) {
                client.writer.println(htmlMessage);
            }
        }
    }

    static class MessageRenderer {
        // 漏洞点：直接拼接用户输入到HTML内容中
        static String createWelcomeMessage(String username) {
            return "<html><body><b>" + username + "</b> 加入了游戏</body></html>";
        }

        // 漏洞点：直接将用户输入插入到HTML中
        static String createChatMessage(String username, String message) {
            return "<html><body><b>" + username + "</b>: " + message + "</body></html>";
        }
    }
}

// 模拟客户端代码（简化版）
class GameClient extends JFrame {
    private JTextPane displayArea;
    private JTextField inputField;
    private String username;

    public GameClient(String username) {
        this.username = username;
        setupUI();
        connectToServer();
    }

    private void setupUI() {
        displayArea = new JTextPane();
        displayArea.setContentType("text/html");
        inputField = new JTextField();
        
        inputField.addActionListener(e -> {
            String message = inputField.getText();
            sendToServer(message);
            inputField.setText("");
        });
        
        add(new JScrollPane(displayArea), BorderLayout.CENTER);
        add(inputField, BorderLayout.SOUTH);
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
    }

    private void connectToServer() {
        try {
            Socket socket = new Socket("localhost", 8080);
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            writer.println(username);
            
            new Thread(() -> {
                try {
                    String html;
                    while ((html = reader.readLine()) != null) {
                        displayArea.setText(html);
                    }
                } catch (IOException e) {}
            }).start();
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void sendToServer(String message) {
        try {
            Socket socket = new Socket("localhost", 8080);
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            writer.println(username);
            writer.println(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}