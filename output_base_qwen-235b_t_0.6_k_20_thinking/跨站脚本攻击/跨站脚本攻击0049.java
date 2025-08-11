import java.io.*;
import java.net.*;
import java.util.*;
import org.jsoup.*;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

interface Crawler {
    void startCrawling(String startUrl);
    String generateReport();
}

class WebCrawler implements Crawler {
    private Set<String> visitedUrls = new HashSet<>();
    private Map<String, String> crawledContent = new HashMap<>();
    private HtmlParser htmlParser;

    public WebCrawler() {
        this.htmlParser = new HtmlParser();
    }

    @Override
    public void startCrawling(String startUrl) {
        crawl(startUrl);
    }

    private void crawl(String url) {
        if (visitedUrls.contains(url)) return;
        
        try {
            Document doc = Jsoup.connect(url).get();
            String content = htmlParser.extractContent(doc);
            crawledContent.put(url, content);
            
            for (Element link : doc.select("a[href]")) {
                String nextUrl = link.absUrl("href");
                crawl(nextUrl);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public String generateReport() {
        StringBuilder report = new StringBuilder("<html><body>");
        report.append("<h1>Crawl Report</h1>");
        
        for (Map.Entry<String, String> entry : crawledContent.entrySet()) {
            report.append("<div><h3>")
                   .append(entry.getKey())
                   .append("</h3>")
                   .append(entry.getValue()) // Vulnerable line: directly inserting raw HTML
                   .append("</div>");
        }
        
        report.append("</body></html>");
        return report.toString();
    }
}

class HtmlParser {
    public String extractContent(Document doc) {
        return doc.body().html(); // Returns raw HTML content
    }
}

public class Main {
    public static void main(String[] args) {
        Crawler crawler = new WebCrawler();
        crawler.startCrawling("https://example.com");
        System.out.println(crawler.generateReport());
    }
}