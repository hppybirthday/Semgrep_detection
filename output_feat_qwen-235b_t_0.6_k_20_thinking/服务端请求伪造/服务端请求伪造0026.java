import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@SpringBootApplication
@RestController
@RequestMapping("/api/logs")
public class LogProcessor {

    public static void main(String[] args) {
        SpringApplication.run(LogProcessor.class, args);
    }

    @GetMapping("/process")
    public String processLog(@RequestParam String logId) {
        String executorAddress = "http://log-service/internal/" + logId;
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(executorAddress);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                // 模拟数据清洗操作
                return "Cleaned Data: " + responseBody.replaceAll("\\s+", " ");
            }
        } catch (IOException e) {
            return "Error processing log: " + e.getMessage();
        }
    }

    // 模拟内部元数据接口
    @GetMapping("/internal/metadata")
    private String internalMetadata() {
        return "SECRET_TOKEN=abc123; INTERNAL_PORT=8080";
    }
}
// 编译要求：需要Spring Boot 2.7+和Apache HttpClient 4.5+依赖