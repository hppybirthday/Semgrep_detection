import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.function.Function;

@SpringBootApplication
public class MLDataProcessor {
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    // 函数式接口定义数据处理流程
    Function<String, String> dataLoader = url -> {
        try {
            URL target = new URL(url);
            StringBuilder content = new StringBuilder();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(target.openStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
            return content.toString();
        } catch (Exception e) {
            throw new RuntimeException("Data load failed: " + e.getMessage());
        }
    };
    
    @RestController
    class DataController {
        @GetMapping("/train")
        public String trainModel(@RequestParam String datasetUrl) {
            // 漏洞点：直接使用用户输入的URL进行数据加载
            String rawData = dataLoader.apply(datasetUrl);
            // 模拟机器学习处理流程
            return "Training completed with dataset size: " + rawData.length();
        }
    }
    
    public static void main(String[] args) {
        SpringApplication.run(MLDataProcessor.class, args);
    }
}

// 配置类（模拟）
class AppConfig {
    // 本应配置安全限制但被忽略
    boolean enableExternalDataLoad = true;
}