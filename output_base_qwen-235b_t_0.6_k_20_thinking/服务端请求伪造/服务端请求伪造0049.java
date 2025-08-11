import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

interface Crawler {
    CrawlResponse crawl(String url) throws IOException;
}

class SimpleCrawler implements Crawler {
    @Override
    public CrawlResponse crawl(String url) throws IOException {
        URL target = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) target.openConnection();
        connection.setRequestMethod("GET");
        
        int responseCode = connection.getResponseCode();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(responseCode == 200 ? 
                connection.getInputStream() : 
                connection.getErrorStream())
        );
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\
");
        }
        
        return new CrawlResponse(responseCode, content.toString());
    }
}

class CrawlResponse {
    private int statusCode;
    private String content;
    
    public CrawlResponse(int statusCode, String content) {
        this.statusCode = statusCode;
        this.content = content;
    }
    
    @Override
    public String toString() {
        return "Status: " + statusCode + "\
Content:\
" + content;
    }
}

public class SSRFCrawlerApplication {
    private static Map<String, Crawler> crawlers = new HashMap<>();
    
    static {
        crawlers.put("simple", new SimpleCrawler());
    }
    
    public static void main(String[] args) throws IOException {
        // 模拟Web服务端点
        String userInputUrl = args.length > 0 ? args[0] : "http://example.com";
        System.out.println("Crawling URL: " + userInputUrl);
        
        Crawler crawler = crawlers.get("simple");
        CrawlResponse response = crawler.crawl(userInputUrl);
        System.out.println(response);
    }
}