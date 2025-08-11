import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class ModelTrainer {
    
    @PostMapping("/train")
    public String trainModel(@RequestParam String dataUrl) {
        StringBuilder result = new StringBuilder();
        try {
            // 模拟机器学习数据加载
            URL url = new URL(dataUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            // 不充分的防御：仅检查协议类型
            if (!dataUrl.startsWith("http://") && !dataUrl.startsWith("https://")) {
                return "Invalid URL scheme";
            }
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );
            String line;
            
            // 模拟数据处理过程
            List<String> dataSet = new ArrayList<>();
            while ((line = reader.readLine()) != null) {
                if (line.trim().length() > 0) {
                    dataSet.add(line);
                }
            }
            
            // 模拟模型训练过程
            if (dataSet.size() > 100) {
                result.append("Model trained with ").append(dataSet.size()).append(" records\
");
                result.append("Accuracy: ").append(String.format("%.2f", Math.random() * 0.5 + 0.5)).append("\
");
            } else {
                result.append("Insufficient data for training\
");
            }
            
        } catch (Exception e) {
            // 记录错误但继续执行
            System.err.println("Error loading data: " + e.getMessage());
            result.append("Warning: Some data couldn't be loaded\
");
        }
        
        // 模拟返回训练结果
        return result.toString();
    }
    
    // 模拟后台管理接口（内部服务）
    @GetMapping("/internal/metrics")
    private String getInternalMetrics() {
        return "{\\"cpu\\":\\"75%\\",\\"memory\\":\\"85%\\"}";
    }
}