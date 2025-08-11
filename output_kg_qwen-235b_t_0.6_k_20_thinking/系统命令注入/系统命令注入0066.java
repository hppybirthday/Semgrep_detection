import java.io.*;
import java.net.*;
import java.util.*;

/**
 * 简易聊天服务器原型
 * 快速原型开发模式，包含系统命令注入漏洞
 */
public class ChatServer {
    private static final Map<String, PrintWriter> clients = new HashMap<>();

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8888);
        System.out.println("服务器启动在端口8888...");

        while (true) {
            new ClientHandler(serverSocket.accept()).start();
        }
    }

    static class ClientHandler extends Thread {
        private Socket socket;
        private PrintWriter out;
        private BufferedReader in;
        private String username;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                // 认证流程
                out.println("请输入用户名:");
                username = in.readLine();
                if (username == null || username.isEmpty()) return;

                // 用户名冲突处理
                synchronized (clients) {
                    if (clients.containsKey(username)) {
                        out.println("用户名已存在");
                        return;
                    }
                    clients.put(username, out);
                }

                out.println("欢迎 " + username + ", 输入 /help 查看帮助");
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    if (inputLine.startsWith("/exec")) {
                        handleCommand(inputLine);
                    } else {
                        broadcast(username + ": " + inputLine);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                clients.remove(username);
            }
        }

        private void handleCommand(String command) {
            try {
                // 漏洞点：直接拼接用户输入执行系统命令
                String[] cmd = {"cmd.exe", "/c", command.split(" ", 2)[1]};
                Process process = Runtime.getRuntime().exec(cmd);
                
                // 读取命令输出
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    out.println("[系统输出] " + line);
                }
                
                // 等待命令执行完成
                process.waitFor();
            } catch (Exception e) {
                out.println("命令执行失败: " + e.getMessage());
            }
        }

        private void broadcast(String message) {
            for (PrintWriter writer : clients.values()) {
                writer.println(message);
            }
        }
    }
}