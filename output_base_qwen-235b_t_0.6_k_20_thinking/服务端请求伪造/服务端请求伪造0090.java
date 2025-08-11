import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Server started on port 8080");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            handleRequest(clientSocket);
        }
    }

    private static void handleRequest(Socket socket) {
        try (Scanner in = new Scanner(socket.getInputStream());
             OutputStream out = socket.getOutputStream()) {

            // 读取HTTP请求
            String request = in.nextLine();
            while (in.hasNextLine() && !in.nextLine().isEmpty()) {}

            // 解析URL参数
            String[] parts = request.split(" ");
            if (parts.length < 2) return;

            String query = new URI(parts[1]).getQuery();
            if (query == null || !query.startsWith("url=")) return;

            String targetUrl = query.substring(4);
            
            // 存在漏洞的代码：直接使用用户输入的URL发起请求
            String result = fetchDataFromExternalSource(targetUrl);
            
            // 发送HTTP响应
            String response = "HTTP/1.1 200 OK\\r\
Content-Type: text/html\\r\
\\r\
" + result;
            out.write(response.getBytes());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 存在漏洞的方法：未验证用户输入
    private static String fetchDataFromExternalSource(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            // 模拟数据清洗过程
            Scanner scanner = new Scanner(connection.getInputStream());
            StringBuilder result = new StringBuilder();
            while (scanner.hasNext()) {
                result.append(scanner.nextLine()).append("\
");
            }
            scanner.close();
            return result.toString();
            
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }
}