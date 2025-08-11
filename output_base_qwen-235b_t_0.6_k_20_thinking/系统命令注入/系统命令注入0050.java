import java.io.*;
import java.net.*;
import java.util.*;

public class ChatServer {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8888);
        System.out.println("服务器启动在端口 8888");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            handleClient(clientSocket);
        }
    }

    private static void handleClient(Socket socket) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("收到消息: " + inputLine);

                if (inputLine.startsWith("!ping ")) {
                    String host = inputLine.substring(6);
                    String command = "ping -c 4 " + host;  // 漏洞点：直接拼接用户输入
                    
                    Process process = Runtime.getRuntime().exec(command.split(" "));
                    BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    
                    String s;
                    StringBuilder response = new StringBuilder("Ping结果:\
");
                    while ((s = stdInput.readLine()) != null) {
                        response.append(s).append("\
");
                    }
                    out.println(response.toString());
                } 
                else if (inputLine.equals("!exit")) {
                    out.println("断开连接");
                    break;
                }
                else {
                    out.println("收到消息: " + inputLine);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}