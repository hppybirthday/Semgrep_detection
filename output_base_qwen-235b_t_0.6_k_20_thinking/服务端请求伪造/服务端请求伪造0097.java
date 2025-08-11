import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.HttpURLConnection;

// 应用层
public class CrawlerApplication {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java CrawlerApplication <url>");
            return;
        }
        
        CrawlerService crawler = new CrawlerService();
        try {
            String result = crawler.crawl(args[0]);
            System.out.println("Content length: " + result.length());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

// 领域服务
class CrawlerService {
    private final WebClient webClient = new WebClient();

    public String crawl(String targetUrl) throws IOException {
        // 漏洞点：直接使用用户输入的URL
        return webClient.fetchContent(targetUrl);
    }
}

// 基础设施层
class WebClient {
    public String fetchContent(String urlString) throws IOException {
        StringBuilder content = new StringBuilder();
        
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        
        return content.toString();
    }
}