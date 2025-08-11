import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}

@RestController
class ThumbnailController {
    private final ThumbnailService thumbnailService = new ThumbnailService();

    @GetMapping("/thumbnail")
    public ResponseEntity<String> generateThumbnail(@RequestParam String imageUrl) {
        try {
            String result = thumbnailService.fetchImageAndGenerateThumbnail(imageUrl);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing request");
        }
    }
}

class ThumbnailService {
    String fetchImageAndGenerateThumbnail(String imageUrl) throws IOException {
        // 模拟创建缩略图的业务逻辑
        String thumbnailUrl = "http://image-processing.service/resize?url=" + imageUrl + "&size=100x100";
        
        // 使用Apache HttpClient发起请求（漏洞点）
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(thumbnailUrl);
            HttpResponse response = httpClient.execute(request);
            
            // 解析响应内容并返回结果
            String responseBody = EntityUtils.toString(response.getEntity());
            return "Thumbnail generated: " + responseBody;
        }
    }
}

// 攻击示例：
// curl "http://localhost:8080/thumbnail?imageUrl=http://169.254.169.254/latest/meta-data/instance-id"
// 将导致服务器访问元数据服务获取敏感信息