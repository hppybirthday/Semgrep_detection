import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

// 数学建模中的气象数据获取模块
class WeatherDataFetcher {
    // 模拟从外部API获取气象数据（存在SSRF漏洞）
    public String fetchWeatherData(String apiUrl) throws IOException {
        URL url = new URL(apiUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        StringBuilder response = new StringBuilder();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
        }
        return response.toString();
    }
}

// 数学仿真主程序
class MathModelSimulator {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        WeatherDataFetcher fetcher = new WeatherDataFetcher();
        
        System.out.println("=== 数学建模气象仿真系统 ===");
        System.out.println("请输入气象数据源URL（示例：https://api.weatherapi.com/v1/current.json?key=API_KEY&q=Beijing）:");
        String userInputUrl = scanner.nextLine();
        
        try {
            System.out.println("正在获取气象数据...");
            String rawData = fetcher.fetchWeatherData(userInputUrl);
            System.out.println("数据获取成功，原始数据长度：" + rawData.length());
            // 此处应包含数据处理逻辑
            System.out.println("数据处理完成");
        } catch (IOException e) {
            System.err.println("数据获取失败: " + e.getMessage());
        }
    }
}

// 启动类
class SSRFDemo {
    public static void main(String[] args) {
        MathModelSimulator.main(args);
    }
}