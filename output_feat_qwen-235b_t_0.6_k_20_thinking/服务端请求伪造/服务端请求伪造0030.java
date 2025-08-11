import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class DataSourceConfigService {
    private static final Pattern ALLOWED_PROTOCOLS = Pattern.compile("^https?://");

    public Map<String, Object> updateDataSource(String requestUri) {
        try {
            // 漏洞点：直接拼接用户输入的URL
            URL targetUrl = new URL(requestUri);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");

            // 模拟解析JSON响应
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 简单解析JSON（实际应使用JSON库）
            Map<String, Object> result = new HashMap<>();
            if (response.toString().contains("{\\"data\\":")) {
                result.put("status", "success");
                result.put("data", response.toString().substring(8, 20)); // 泄露部分数据
            } else {
                result.put("status", "error");
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            return error;
        }
    }

    // 模拟Dubbo服务接口
    public static class DataSourceConfigController {
        public static void main(String[] args) {
            DataSourceConfigService service = new DataSourceConfigService();
            // 模拟移动应用请求参数
            String userInput = "file:///etc/passwd"; // 恶意输入
            Map<String, Object> response = service.updateDataSource(userInput);
            System.out.println("Response: " + response);
        }
    }
}