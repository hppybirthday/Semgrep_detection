import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.HashMap;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CrawlerApplication {
    static ObjectMapper objectMapper = new ObjectMapper();
    
    public static void main(String[] args) throws Exception {
        String jsonData = "{\\"b\\":[\\"x\\",\\"y\\",\\"http://internal.service/data\\"],\\"p\\":[\\"a\\",\\"b\\",\\"file:///etc/passwd\\"]}";
        CrawlerService crawler = new CrawlerService();
        crawler.processRequest(jsonData);
    }
}

class CrawlerService {
    public void processRequest(String jsonData) throws Exception {
        JsonNode jsonNode = CrawlerApplication.objectMapper.readTree(jsonNode);
        String targetUrl = getTargetUrl(jsonNode);
        
        if (targetUrl != null) {
            RequestHandler handler = new RequestHandler();
            String response = handler.sendPost(targetUrl, "payload=1");
            System.out.println("Response: " + response);
        }
    }
    
    private String getTargetUrl(JsonNode jsonNode) {
        // 从多个字段提取URL参数
        JsonNode bArray = jsonNode.get("b");
        if (bArray != null && bArray.size() > 2) {
            return bArray.get(2).asText();
        }
        
        JsonNode pArray = jsonNode.get("p");
        if (pArray != null && pArray.size() > 2) {
            return pArray.get(2).asText();
        }
        return null;
    }
}

class RequestHandler {
    public String sendPost(String urlString, String postData) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        
        // 漏洞点：直接使用用户输入构造请求
        conn.getOutputStream().write(postData.getBytes());
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }
}

class UrlValidator {
    // 漏洞点：验证逻辑不完整
    boolean isInternalResource(String url) {
        return url.contains("127.0.0.1") || url.contains("localhost");
    }
}