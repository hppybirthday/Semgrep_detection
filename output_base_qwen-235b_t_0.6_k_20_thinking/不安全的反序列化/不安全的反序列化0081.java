import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class VulnerableCrawlerApp {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApp.class, args);
    }
}

@Component
class CrawlerService {
    @Value("${target.url}")
    private String targetUrl;

    public Object crawlAndProcess() throws Exception {
        URL url = new URL(targetUrl);
        try (InputStream is = url.openStream();
             ObjectInputStream ois = new ObjectInputStream(is)) {
            // 危险操作：直接反序列化网络输入流
            return ois.readObject();
        }
    }
}

@RestController
class CrawlerController {
    private final CrawlerService crawlerService;

    @Autowired
    public CrawlerController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    @GetMapping("/trigger")
    public String triggerCrawl() {
        try {
            Object result = crawlerService.crawlAndProcess();
            return "Crawled result: " + result.toString();
        } catch (Exception e) {
            return "Error during crawling: " + e.getMessage();
        }
    }
}

// 攻击者构造的恶意序列化类
class MaliciousPayload implements Serializable {
    private String command;

    public MaliciousPayload(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 恶意代码执行
        Runtime.getRuntime().exec(command);
    }
}