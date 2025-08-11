import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class DataCleanerService {
    public String processUserRequest(String username, String method, String requestUri) {
        String apiUrl = "http://ace-admin/api/user/" + username + "/check_permission?requestMethod=" + method + "&requestUri=" + requestUri;
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(apiUrl);
            HttpResponse response = httpClient.execute(request);
            
            // 模拟数据清洗逻辑
            BufferedReader reader = new BufferedReader(
                new FileReader("/tmp/raw_data.csv"));
            StringBuilder cleanedData = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                cleanedData.append(line.replaceAll("[^a-zA-Z0-9]", ""))
                             .append("\
");
            }
            
            // 存储清洗后的数据
            Path outputPath = Paths.get("/tmp/cleaned_data.txt");
            Files.write(outputPath, cleanedData.toString().getBytes());
            
            return "Processing complete. Result stored at: " + outputPath.toString();
            
        } catch (IOException e) {
            return "Error processing request: " + e.getMessage();
        }
    }
}

// Controller层示例
@RestController
@RequestMapping("/api/data")
public class DataController {
    @Autowired
    private DataCleanerService dataCleanerService;
    
    @GetMapping("/process")
    public String handleProcess(
        @RequestParam String username,
        @RequestParam String method,
        @RequestParam String requestUri) {
        return dataCleanerService.processUserRequest(username, method, requestUri);
    }
}