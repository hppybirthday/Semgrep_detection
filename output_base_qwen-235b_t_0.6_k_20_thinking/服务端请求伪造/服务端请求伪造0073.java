import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

// 模拟大数据处理中心
class DataProcessor {
    // 模拟数据源配置
    private String dataSourceUrl;
    
    public DataProcessor(String dataSourceUrl) {
        this.dataSourceUrl = dataSourceUrl;
    }
    
    // 核心漏洞点：未验证用户输入的URL
    public List<String> fetchExternalData() throws IOException {
        List<String> result = new ArrayList<>();
        URL url = new URL(dataSourceUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // 模拟大数据处理的响应处理
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.add(line);
            }
        }
        
        return result;
    }
}

// 模拟数据处理服务
class DataService {
    // 模拟用户输入处理
    public List<String> processUserRequest(String userInput) throws IOException {
        DataProcessor processor = new DataProcessor(userInput);
        return processor.fetchExternalData();
    }
}

// 模拟主程序入口
public class Main {
    public static void main(String[] args) {
        System.out.println("大数据处理系统 v1.0");
        System.out.print("请输入数据源URL: ");
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in))) {
            String userInput = reader.readLine();
            DataService service = new DataService();
            
            // 执行存在漏洞的数据处理
            List<String> data = service.processUserRequest(userInput);
            System.out.println("成功获取数据记录: " + data.size() + " 条");
            
        } catch (IOException e) {
            System.err.println("数据处理失败: " + e.getMessage());
        }
    }
}