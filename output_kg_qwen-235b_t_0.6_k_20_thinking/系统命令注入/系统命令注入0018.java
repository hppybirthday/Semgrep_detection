import java.io.*;
import java.util.*;

class ChatServer {
    public static void main(String[] args) throws Exception {
        while (true) {
            System.out.print("[Client]: ");
            String input = new BufferedReader(new InputStreamReader(System.in)).readLine();
            if (input.startsWith("/download ")) {
                String filename = input.substring(8);
                ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cat /shared/" + filename);
                Process p = pb.start();
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[Server]: " + line);
                }
            } else if (input.equals("/exit")) {
                break;
            } else {
                System.out.println("[Server]: Unknown command");
            }
        }
    }
}

/*
[Developer's Mistake]
1. 直接拼接用户输入构造系统命令
2. 未过滤特殊字符（如;|&$`\
）
3. 使用bash -c执行动态拼接的字符串
4. 错误示例：输入"/download file.txt; rm -rf /"
*/