import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

// 领域模型：爬虫任务
class CrawlerTask {
    private final String targetUrl;
    private final String outputDir;

    public CrawlerTask(String targetUrl, String outputDir) {
        this.targetUrl = targetUrl;
        this.outputDir = outputDir;
    }

    // 执行爬虫任务（存在漏洞的实现）
    public void execute() {
        try {
            String command = String.format("curl -o %s %s", outputDir, targetUrl);
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 应用服务：爬虫调度器
class CrawlerScheduler {
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    // 通过HTTP参数动态创建任务（关键漏洞触发点）
    public void scheduleCrawl(String url, String dir) {
        CrawlerTask task = new CrawlerTask(url, dir);
        scheduler.schedule(task::execute, 0, TimeUnit.SECONDS);
    }
}

// 模拟Web控制器（攻击面入口）
public class CrawlerController {
    public static void main(String[] args) {
        CrawlerScheduler scheduler = new CrawlerScheduler();
        
        // 模拟用户输入（攻击者可控制输入）
        String userInputUrl = args[0];  // 例如输入："http://example.com; rm -rf /"
        String outputDir = "/tmp/crawl_output";
        
        System.out.println("[+] 开始执行爬虫任务...");
        scheduler.scheduleCrawl(userInputUrl, outputDir);
    }
}