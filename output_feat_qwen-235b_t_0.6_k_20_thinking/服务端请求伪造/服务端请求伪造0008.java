import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class MLModelController {
    private final AdminGoodsService service = new AdminGoodsService();

    @GetMapping("/data")
    public String getExternalData(@RequestParam String url) throws Exception {
        return service.fetchRemoteDataset(url);
    }
}

class AdminGoodsService {
    String fetchRemoteDataset(String datasetUrl) throws Exception {
        URL url = new URL(datasetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }
}

// 模拟启动类
@SpringBootApplication
public class SSRFApplication {
    public static void main(String[] args) {
        SpringApplication.run(SSRFApplication.class, args);
    }
}