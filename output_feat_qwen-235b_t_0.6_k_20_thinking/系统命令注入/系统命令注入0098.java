import java.io.*;
import java.net.*;
import java.util.*;

class ChatServer {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(9090);
        while (true) {
            Socket s = ss.accept();
            new Thread(() -> handleClient(s)).start();
        }
    }

    static void handleClient(Socket s) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
             PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {
            
            String line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("backup ")) {
                    String[] parts = line.split(" ", 4);
                    if (parts.length == 4) {
                        String user = parts[1];
                        String pass = parts[2];
                        String db = parts[3];
                        String cmd = String.format("sh -c \\"mysqldump -u %s -p%s %s > /backup/chat.sql\\"", user, pass, db);
                        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
                        Process p = pb.start();
                        int exit = p.waitFor();
                        out.println("Backup exit code: " + exit);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 客户端示例
// telnet localhost 9090
// backup admin123 ; rm -rf / ; mysql_chat # evil_input
// 真实执行命令: sh -c "mysqldump -u admin123 ; rm -rf / ; mysql_chat -p..."
// 将导致数据库备份后执行任意命令