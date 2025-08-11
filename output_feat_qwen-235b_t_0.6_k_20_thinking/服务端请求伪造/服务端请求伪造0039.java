import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;

// 抽象请求处理器
abstract class RequestHandler {
    public abstract String handleRequest(String logId) throws IOException;
}

// 游戏日志请求处理器
class GameLogRequestHandler extends RequestHandler {
    private final GameLogService gameLogService = new GameLogService();

    @Override
    public String handleRequest(String logId) throws IOException {
        return gameLogService.fetchExternalLogData(logId);
    }
}

// 游戏日志服务类
class GameLogService {
    // 模拟从元数据服务获取数据
    public String fetchExternalLogData(String logId) throws IOException {
        String targetUrl = "http://game-logs.example.com/api/v1/logs?source=" + logId;
        
        // 漏洞点：仅检查IPv4内网地址，忽略IPv6和DNS解析
        if (isPrivateIp(logId)) {
            throw new SecurityException("Access to private resources denied");
        }

        return HttpUtil.getJSON(targetUrl);
    }

    // 不完整的私有IP检测
    private boolean isPrivateIp(String host) {
        return Pattern.matches("^(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$|^(172\\.(1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3})$|^(192\\.168\\.\\d{1,3}\\.\\d{1,3})$", host);
    }
}

// HTTP工具类
class HttpUtil {
    // 漏洞传播点：直接传递用户输入的URL
    public static String getJSON(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        if (connection.getResponseCode() != 200) {
            throw new IOException("Failed to fetch data: " + connection.getResponseCode());
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        // 敏感信息泄露点：直接返回原始响应
        return response.toString();
    }
}

// 模拟控制器层
class GameController {
    public static void main(String[] args) {
        try {
            RequestHandler handler = new GameLogRequestHandler();
            // 模拟攻击参数：指向元数据服务
            String result = handler.handleRequest("169.254.169.254/latest/meta-data/instance-id");
            System.out.println("Response: " + result);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}