import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

// 高抽象建模风格的爬虫核心接口
interface Crawler {
    void startCrawling(String targetUrl, int depth) throws IOException;
}

// 抽象爬虫实现类
abstract class AbstractCrawler implements Crawler {
    protected abstract String buildCrawlCommand(String targetUrl, int depth);
    
    @Override
    public void startCrawling(String targetUrl, int depth) throws IOException {
        String command = buildCrawlCommand(targetUrl, depth);
        executeCommand(command);
    }
    
    // 存在漏洞的命令执行方法
    private void executeCommand(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Crawl Output]: " + line);
            }
        }
    }
}

// 具体网络爬虫实现
class WebCrawler extends AbstractCrawler {
    private final String crawlerScriptPath;
    
    public WebCrawler(String scriptPath) {
        this.crawlerScriptPath = scriptPath;
    }
    
    @Override
    protected String buildCrawlCommand(String targetUrl, int depth) {
        // 漏洞根源：直接拼接用户输入参数
        return String.format("python %s --url %s --depth %d", 
                           crawlerScriptPath, targetUrl, depth);
    }
}

// 模拟爬虫控制器
public class CrawlerController {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java CrawlerController <scriptPath> <targetUrl> <depth>");
            return;
        }
        
        try {
            // 高抽象建模的爬虫实例创建
            Crawler crawler = new WebCrawler(args[0]);
            // 漏洞触发点：用户输入直接传递给命令构造
            crawler.startCrawling(args[1], Integer.parseInt(args[2]));
        } catch (Exception e) {
            System.err.println("Crawling failed: " + e.getMessage());
        }
    }
}