import java.io.*;
import java.util.Scanner;

interface Crawler {
    void crawl(String targetUrl) throws IOException;
}

abstract class AbstractCrawler implements Crawler {
    protected String userAgent;
    
    public AbstractCrawler(String userAgent) {
        this.userAgent = userAgent;
    }
}

class WgetCrawler extends AbstractCrawler {
    public WgetCrawler(String userAgent) {
        super(userAgent);
    }

    @Override
    public void crawl(String targetUrl) throws IOException {
        String command = String.format("wget -U \\"%s\\" -O /tmp/crawl_result.html %s", 
            userAgent, targetUrl);
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            System.out.println("Crawl completed with exit code: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Crawl interrupted", e);
        }
    }
}

class CrawlerFactory {
    static Crawler createCrawler(String userAgent) {
        return new WgetCrawler(userAgent);
    }
}

public class VulnerableWebCrawler {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter target URL: ");
        String targetUrl = scanner.nextLine();
        
        System.out.print("Enter user agent: ");
        String userAgent = scanner.nextLine();
        
        try {
            Crawler crawler = CrawlerFactory.createCrawler(userAgent);
            crawler.crawl(targetUrl);
        } catch (IOException e) {
            System.err.println("Crawl failed: " + e.getMessage());
        }
        
        scanner.close();
    }
}