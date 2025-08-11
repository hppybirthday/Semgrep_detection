import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    
    @Autowired
    private TaskService taskService;

    @PostMapping
    public String createTask(@RequestParam String webhookUrl) {
        try {
            return taskService.processWebhook(webhookUrl);
        } catch (Exception e) {
            return "Error processing webhook: " + e.getMessage();
        }
    }
}

@Service
class TaskService {
    
    @Autowired
    private UrlValidator urlValidator;
    
    @Autowired
    private HttpClientWrapper httpClient;

    public String processWebhook(String webhookUrl) throws Exception {
        if (!urlValidator.isValidUrl(webhookUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // Vulnerable: Blindly follows redirects and accesses any validated URL
        return httpClient.fetchContent(webhookUrl);
    }
}

@Component
class UrlValidator {
    
    // Vulnerable: Only checks protocol but not internal network targets
    public boolean isValidUrl(String url) {
        String urlPattern = "^(https?://).*";
        Pattern pattern = Pattern.compile(urlPattern);
        Matcher matcher = pattern.matcher(url);
        return matcher.find();
    }
}

@Component
class HttpClientWrapper {
    
    public String fetchContent(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // Vulnerable: Follows redirects without validation
        connection.setInstanceFollowRedirects(true);
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream()));
        StringBuilder content = new StringBuilder();
        String inputLine;
        
        while ((inputLine = reader.readLine()) != null) {
            content.append(inputLine);
        }
        reader.close();
        
        return content.toString();
    }
}