import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class MLDataProcessor {

    public static void main(String[] args) {
        SpringApplication.run(MLDataProcessor.class, args);
    }

    @GetMapping("/train")
    public String processTrainingData(@RequestParam String datasetUrl) {
        try {
            // 模拟机器学习数据处理流程
            String rawData = fetchExternalData(datasetUrl);
            String processedData = preprocessData(rawData);
            
            // 模拟模型训练
            return trainModel(processedData);
        } catch (Exception e) {
            return "Error processing data: " + e.getMessage();
        }
    }

    private String fetchExternalData(String datasetUrl) throws Exception {
        // 存在漏洞的代码：直接使用用户输入的URL
        URL url = new URL(datasetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        return response.toString();
    }

    private String preprocessData(String data) {
        // 简单模拟数据预处理
        return data.replaceAll("\\s+", " ").trim();
    }

    private String trainModel(String data) {
        // 模拟模型训练过程
        int featureCount = data.split(" ").length;
        return "Model trained with " + featureCount + " features";
    }
}